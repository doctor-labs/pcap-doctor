"""D23 -- Kerberos and NTLM: deprecated encryption, missing pre-authentication, NTLMv1 and unsigned NTLM (#205)."""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..krb_ntlm import (
    DES_ETYPES,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_TGS_REP,
    NTLMSSP_AUTHENTICATE,
    NTLMSSP_CHALLENGE,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMV1_RESPONSE_LEN,
    PA_ENC_TIMESTAMP,
    WEAK_ETYPES,
    KrbMsg,
)
from ..models import Finding
from ..tshark import to_int
from .base import Detector, ev

RFC_6649 = "RFC 6649"
ATTACK_ASREP = "MITRE ATT&CK T1558.004 (AS-REP Roasting)"
ATTACK_RELAY = "MITRE ATT&CK T1557.001 (LLMNR/NBT-NS/SMB Relay)"
CWE_327 = "CWE-327"


class KerberosNtlmDetector(Detector):
    name: ClassVar[str] = "d23.kerberos_ntlm"
    title: ClassVar[str] = "Kerberos and NTLM weak configuration"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "Credentials"
    description: ClassVar[str] = (
        "Kerberos replies that use DES or RC4-HMAC, AS replies issued without pre-authentication the KDC never "
        "asked for, NTLMv1 authentication responses and NTLM challenges that do not negotiate signing."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def once(code: str, key: str) -> bool:
            if (code, key) in seen:
                return False
            seen.add((code, key))
            return True

        def subjects(key: str) -> list[str]:
            flow = index.flows.get(key)
            return [flow.endpoint_a, flow.endpoint_b] if flow else []

        last_as_req: dict[str, KrbMsg] = {}
        preauth_demanded: set[str] = set()
        for m in index.kerberos:
            if m.msg_type == KRB_AS_REQ:
                last_as_req[m.key] = m
            elif m.msg_type == KRB_ERROR and m.error == KDC_ERR_PREAUTH_REQUIRED:
                # keyed by principal: the client retries from a new source port, so the 5-tuple differs
                preauth_demanded.add(m.client or m.key)
            elif m.msg_type in (KRB_AS_REP, KRB_TGS_REP):
                for etype in sorted({e for e in m.etypes if e in WEAK_ETYPES}):
                    if not once("KERBEROS_WEAK_ETYPE", f"{m.key}|{etype}"):
                        continue
                    des = etype in DES_ETYPES
                    out.append(self.finding(
                        code="KERBEROS_WEAK_ETYPE", title=f"Kerberos {WEAK_ETYPES[etype]} reply on {m.key}",
                        severity="high" if des else "medium", confidence="high",
                        summary=f"A Kerberos {'AS' if m.msg_type == KRB_AS_REP else 'TGS'} reply carries "
                        f"{WEAK_ETYPES[etype]} (etype {etype}) for principal {m.client or 'unknown'}. "
                        "This encryption type is deprecated; its tickets are cheap to crack offline.",
                        scope=f"{m.key}|{WEAK_ETYPES[etype]}", flow_key=m.key, subjects=subjects(m.key),
                        evidence=[ev(m.frame, "kerberos.etype", etype)],
                        remediation="Disable DES and RC4-HMAC for Kerberos (Windows: 'Network security: Configure "
                        "encryption types allowed for Kerberos'; set AES-only on accounts and KDCs), then reissue "
                        "the affected keys.",
                        references=[RFC_6649, CWE_327], tags=["kerberos", "crypto"]))
                if m.msg_type == KRB_AS_REP:
                    req = last_as_req.get(m.key)
                    if (req and PA_ENC_TIMESTAMP not in req.padata
                            and (req.client or req.key) not in preauth_demanded
                            and once("KERBEROS_NO_PREAUTH", m.key)):
                        out.append(self.finding(
                            code="KERBEROS_NO_PREAUTH",
                            title=f"Kerberos AS reply without pre-authentication on {m.key}",
                            severity="medium", confidence="high",
                            summary=f"The KDC issued an AS reply for principal {req.client or 'unknown'} to a request "
                            "with no PA-ENC-TIMESTAMP, and never asked for pre-authentication. The account has "
                            "'do not require Kerberos preauthentication' set, so its hash can be requested and "
                            "cracked offline without a password.",
                            scope=m.key, flow_key=m.key, subjects=subjects(m.key),
                            evidence=[ev(req.frame, "kerberos.padata_type", "none")],
                            remediation="Clear 'Do not require Kerberos preauthentication' on the account (Active "
                            "Directory Users and Computers, or Set-ADAccountControl -DoesNotRequirePreAuth $false), "
                            "and reset its password.",
                            references=[ATTACK_ASREP], tags=["kerberos", "asrep"]))

        # NTLMv1 is reported only for a logon the server accepted (SMB SESSION_SETUP response with status 0).
        # A refused attempt still sends the same response format, but it is not an authenticated session.
        accepted = {op.key for op in index.smb
                    if op.command == "SESSION_SETUP" and op.response and op.status is not None
                    and to_int(op.status, 16) == 0}
        for n in index.ntlm:
            if (n.message_type == NTLMSSP_CHALLENGE and n.flags is not None
                    and not n.flags & NTLMSSP_NEGOTIATE_SIGN and once("NTLM_SIGNING_NOT_NEGOTIATED", n.key)):
                out.append(self.finding(
                    code="NTLM_SIGNING_NOT_NEGOTIATED", title=f"NTLM signing not negotiated on {n.key}",
                    severity="medium", confidence="high",
                    summary="The server's NTLM CHALLENGE does not negotiate message signing, so an on-path "
                    "attacker can relay or tamper with the authenticated session.",
                    scope=n.key, flow_key=n.key, subjects=subjects(n.key),
                    evidence=[ev(n.frame, "ntlmssp.negotiateflags", f"{n.flags:#010x}")],
                    remediation="Require NTLM signing and sealing (Windows: 'Network security: LAN Manager "
                    "authentication level' and 'Require NTLM message signing'), or move to Kerberos.",
                    references=[ATTACK_RELAY], tags=["ntlm", "relay"]))
            if (n.message_type == NTLMSSP_AUTHENTICATE and n.nt_len == NTLMV1_RESPONSE_LEN
                    and n.key in accepted and once("NTLM_V1_AUTH", n.key)):
                out.append(self.finding(
                    code="NTLM_V1_AUTH", title=f"NTLMv1 authentication on {n.key}",
                    severity="high", confidence="high",
                    summary="An NTLM AUTHENTICATE carries a 24-byte response, which is NTLMv1. NTLMv1 responses "
                    "can be cracked or replayed to recover the NT hash.",
                    scope=n.key, flow_key=n.key, subjects=subjects(n.key),
                    evidence=[ev(n.frame, "ntlmssp.blob.length", n.nt_len)],
                    remediation="Set 'LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM "
                    "and NTLM' on clients and servers, and retire the clients that still need NTLMv1.",
                    references=[CWE_327], tags=["ntlm", "legacy"]))
        return out
