"""D23 -- Kerberos and NTLM: deprecated encryption, missing pre-authentication, NTLMv1 and unsigned NTLM (#205, #232).

Without raw response bytes (see core issue for hash extraction) this detector reports the exposure
surface that is visible on the wire: negotiated NTLM properties and identities, unanswered challenges,
NTLMv1 24-byte response lengths (offline-crackable material present) without ever printing response bytes,
and Kerberos ticket issuance/delegation context (krbtgt vs service tickets, and service tickets issued
without a prior successful authentication for the same principal in the capture).
"""

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
    KRB_TGS_REQ,
    NTLMSSP_AUTHENTICATE,
    NTLMSSP_CHALLENGE,
    NTLMSSP_NEGOTIATE,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMV1_RESPONSE_LEN,
    PA_ENC_TIMESTAMP,
    WEAK_ETYPES,
    KrbMsg,
    NtlmMsg,
)
from ..models import Finding
from ..tshark import to_int
from .base import Detector, ev

RFC_6649 = "RFC 6649"
RFC_4120 = "RFC 4120"
ATTACK_ASREP = "MITRE ATT&CK T1558.004 (AS-REP Roasting)"
ATTACK_RELAY = "MITRE ATT&CK T1557.001 (LLMNR/NBT-NS/SMB Relay)"
ATTACK_KERBEROAST = "MITRE ATT&CK T1558.003 (Kerberoasting)"
ATTACK_DELEGATION = "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)"
CWE_327 = "CWE-327"
CWE_522 = "CWE-522"

NTLM_MSG_NAMES = {1: "NEGOTIATE", 2: "CHALLENGE", 3: "AUTHENTICATE"}


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
        authenticated_principals: set[str] = set()
        for m in index.kerberos:
            if m.msg_type == KRB_AS_REQ:
                last_as_req[m.key] = m
            if m.msg_type == KRB_ERROR and m.error == KDC_ERR_PREAUTH_REQUIRED:
                # keyed by principal: the client retries from a new source port, so the 5-tuple differs
                preauth_demanded.add(m.client or m.key)
            if m.msg_type in (KRB_AS_REP, KRB_TGS_REQ) and m.client:
                authenticated_principals.add(m.client)
            if m.msg_type in (KRB_AS_REP, KRB_TGS_REP):
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

        # Kerberos ticket issuance context visible without ticket/key material (#232).
        for m in index.kerberos:
            if m.msg_type not in (KRB_AS_REP, KRB_TGS_REP):
                continue
            service = m.service or "unknown"
            is_tgt = service.startswith("krbtgt/")
            ticket_kind = "krbtgt (TGT)" if is_tgt else "service ticket"
            if once("KERBEROS_TICKET_ISSUED", f"{m.msg_type}|{m.key}|{m.client}|{service}|{m.frame}"):
                out.append(self.finding(
                    code="KERBEROS_TICKET_ISSUED",
                    title=f"Kerberos {ticket_kind} issued on {m.key}",
                    severity="info", confidence="high",
                    summary=f"The KDC issued a {'TGS' if m.msg_type == KRB_TGS_REP else 'AS'} reply granting a "
                    f"{ticket_kind} for service {service} to principal {m.client or 'unknown'} in realm "
                    f"{m.realm or 'unknown'}. Distinguishing krbtgt from service tickets exposes the delegation "
                    "and service-access surface without carrying ticket or key material.",
                    scope=f"issued|{m.msg_type}|{m.key}|{m.client}|{service}",
                    flow_key=m.key, subjects=subjects(m.key),
                    evidence=[ev(m.frame, "kerberos.sname", service),
                              ev(m.frame, "kerberos.cname", m.client or "unknown"),
                              ev(m.frame, "kerberos.realm", m.realm or "unknown")],
                    remediation="Review whether the principal should obtain this ticket. Limit unconstrained/"
                    "constrained delegation and monitor service-ticket issuance for sensitive SPNs.",
                    references=[RFC_4120, ATTACK_DELEGATION],
                    tags=["kerberos", "delegation", "tgt" if is_tgt else "service-ticket"]))
            if m.msg_type == KRB_TGS_REP and not is_tgt:
                principal = m.client or "unknown"
                if principal not in authenticated_principals and once("KERBEROS_TGS_WITHOUT_PRIOR_AUTH", f"{m.key}|{principal}|{service}"):
                    out.append(self.finding(
                        code="KERBEROS_TGS_WITHOUT_PRIOR_AUTH",
                        title=f"Kerberos service ticket without prior authentication on {m.key}",
                        severity="medium", confidence="medium",
                        summary=f"A TGS-REP issued a service ticket for {service} to principal {principal} with no "
                        "successful AS/TGS authentication for that principal observed earlier in the capture. "
                        "This can indicate a delegated, forged, or out-of-window ticket issuance.",
                        scope=f"noauth|{m.key}|{principal}|{service}", flow_key=m.key, subjects=subjects(m.key),
                        evidence=[ev(m.frame, "kerberos.sname", service),
                                  ev(m.frame, "kerberos.cname", principal)],
                        remediation="Correlate with KDC and directory logs. Restrict delegation, enforce PAC "
                        "validation, and investigate unexpected service-ticket grants.",
                        references=[ATTACK_DELEGATION, ATTACK_KERBEROAST],
                        tags=["kerberos", "delegation"]))

        # NTLMv1 is reported only for a logon the server accepted (SMB SESSION_SETUP response with status 0).
        # A refused attempt still sends the same response format, but it is not an authenticated session.
        accepted = {op.key for op in index.smb
                    if op.command == "SESSION_SETUP" and op.response and op.status is not None
                    and to_int(op.status, 16) == 0}

        # Track challenge/response per flow to detect unanswered challenges and negotiate properties (#232).
        by_flow: dict[str, list[NtlmMsg]] = {}
        for n in index.ntlm:
            by_flow.setdefault(n.key, []).append(n)

        for key, msgs in by_flow.items():
            negotiated: NtlmMsg | None = None
            challenged: NtlmMsg | None = None
            authenticated = False
            for n in msgs:
                if n.message_type == NTLMSSP_NEGOTIATE and negotiated is None:
                    negotiated = n
                elif n.message_type == NTLMSSP_CHALLENGE:
                    challenged = n
                elif n.message_type == NTLMSSP_AUTHENTICATE:
                    authenticated = True
            if negotiated and once("NTLM_NEGOTIATION", key):
                alg = "NTLMv1 (24-byte response observed)" if any(m.nt_len == NTLMV1_RESPONSE_LEN for m in msgs if m.message_type == NTLMSSP_AUTHENTICATE) else "NTLMv2/unknown (no 24-byte response observed)"
                out.append(self.finding(
                    code="NTLM_NEGOTIATION", title=f"NTLM negotiation observed on {key}",
                    severity="info", confidence="high",
                    summary=f"An NTLMSSP exchange negotiated authentication on {key}; inferred hash algorithm: {alg}. "
                    "This reports observable negotiation properties only; no challenge, response, or hash material is included.",
                    scope=f"negotiate|{key}", flow_key=key, subjects=subjects(key),
                    evidence=[ev(negotiated.frame, "ntlmssp.messagetype", NTLM_MSG_NAMES.get(negotiated.message_type, negotiated.message_type))],
                    remediation="Prefer Kerberos over NTLM. Where NTLM remains, require NTLMv2, signing, and EPA/channel binding.",
                    references=[ATTACK_RELAY, CWE_522], tags=["ntlm", "negotiation"]))
            if challenged and not authenticated and once("NTLM_CHALLENGE_UNANSWERED", key):
                out.append(self.finding(
                    code="NTLM_CHALLENGE_UNANSWERED", title=f"NTLM challenge never answered on {key}",
                    severity="low", confidence="high",
                    summary="The server issued an NTLM CHALLENGE but no AUTHENTICATE message followed on the same flow. "
                    "An unanswered challenge can indicate probing, coercion attempts, or a client refusing NTLM.",
                    scope=f"unanswered|{key}", flow_key=key, subjects=subjects(key),
                    evidence=[ev(challenged.frame, "ntlmssp.messagetype", NTLM_MSG_NAMES.get(challenged.message_type, challenged.message_type))],
                    remediation="Investigate the source of the negotiation. Disable NTLM where possible and alert on unsolicited NTLM challenges/coercion.",
                    references=[ATTACK_RELAY], tags=["ntlm", "challenge"]))

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
            if n.message_type == NTLMSSP_AUTHENTICATE:
                acct = n.username or "unknown"
                dom = n.domain or "unknown"
                is_accepted = n.key in accepted
                outcome = "accepted" if is_accepted else "not accepted/unknown"
                if once("NTLM_IDENTITY_EXPOSED", f"{n.key}|{acct}|{dom}|{is_accepted}"):
                    out.append(self.finding(
                        code="NTLM_IDENTITY_EXPOSED",
                        title=f"NTLM account identity observed on {n.key}",
                        severity="info", confidence="high",
                        summary=f"An NTLM AUTHENTICATE exposes account {acct} in domain {dom} for an exchange that is "
                        f"{outcome} by the server. No response or hash material is included.",
                        scope=f"identity|{n.key}|{acct}|{dom}|{is_accepted}",
                        flow_key=n.key, subjects=subjects(n.key),
                        evidence=[ev(n.frame, "ntlmssp.auth.username", acct),
                                  ev(n.frame, "ntlmssp.auth.domain", dom),
                                  ev(n.frame, "smb2.session.setup.accepted", "true" if is_accepted else "false")],
                        remediation="Limit NTLM exposure, require signing/EPA, and monitor for unexpected account use.",
                        references=[CWE_522], tags=["ntlm", "identity"]))
                if n.nt_len == NTLMV1_RESPONSE_LEN and once("NTLM_HASH_OFFLINE_CRACKABLE", f"{n.key}|{acct}|{dom}"):
                    out.append(self.finding(
                        code="NTLM_HASH_OFFLINE_CRACKABLE",
                        title=f"NTLMv1 offline-crackable response length on {n.key}",
                        severity="high", confidence="high",
                        summary=f"An NTLM AUTHENTICATE for account {acct} in domain {dom} carries a 24-byte NT response, "
                        "indicating NTLMv1 challenge-response material is present on the wire and is offline-crackable. "
                        "The response bytes are not reported.",
                        scope=f"hashlen|{n.key}|{acct}|{dom}", flow_key=n.key, subjects=subjects(n.key),
                        evidence=[ev(n.frame, "ntlmssp.blob.length", n.nt_len),
                                  ev(n.frame, "ntlmssp.auth.username", acct),
                                  ev(n.frame, "ntlmssp.auth.domain", dom)],
                        remediation="Disable NTLMv1 and require NTLMv2 only ('LAN Manager authentication level' -> "
                        "'Send NTLMv2 response only. Refuse LM and NTLM'), then rotate affected credentials.",
                        references=[CWE_327, ATTACK_RELAY], tags=["ntlm", "hash-exposure"]))
                if n.nt_len == NTLMV1_RESPONSE_LEN and is_accepted and once("NTLM_V1_AUTH", n.key):
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
