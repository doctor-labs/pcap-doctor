"""D25 -- Kerberos exchange dissection: who authenticated, to which realm, for which service (#205).

The Kerberos pass already yields the principal, realm and service of every message it sees; this
detector turns that into an inventory an analyst can act on and flags the two shapes that matter
without any prior knowledge of the environment: a service ticket that no AS exchange in this capture
issued, and a reply that names no principal at all.

Only names, realms, service names and message types are used. No ticket, key or ciphertext is read.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..krb_ntlm import KRB_AS_REP, KRB_AS_REQ, KRB_TGS_REP
from ..models import Finding
from .base import Detector, ev

RFC_4120 = "RFC 4120"
RFC_6113 = "RFC 6113"
ATTACK_DELEGATION = "MITRE ATT&CK T1558.003 (Steal or Forge Kerberos Tickets: delegation)"


class KerberosAuthDetector(Detector):
    name: ClassVar[str] = "d25.kerberos_auth"
    title: ClassVar[str] = "Kerberos authentication inventory"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "Credentials"
    description: ClassVar[str] = (
        "Which Kerberos principal authenticated to which realm and obtained a service ticket for which "
        "service, service tickets issued without an AS exchange in this capture, and replies that carry "
        "a realm but no client principal."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()

        # A principal counts as authenticated when it appears in an AS request or reply. The client
        # retries from a new source port after the KDC demands pre-authentication, so the AS exchange
        # can sit on a different flow key than the service ticket that follows it.
        authenticated: set[str] = set()
        for m in index.kerberos:
            if m.msg_type in (KRB_AS_REQ, KRB_AS_REP) and m.client:
                authenticated.add(m.client)

        def subjects(key: str) -> list[str]:
            flow = index.flows.get(key)
            return [flow.endpoint_a, flow.endpoint_b] if flow else []

        for m in index.kerberos:
            if m.msg_type not in (KRB_AS_REP, KRB_TGS_REP):
                continue
            service = m.service or ""
            principal = m.client

            if principal and service:
                scope = f"{principal}|{m.realm or ''}|{service}"
                if scope not in seen:
                    seen.add(scope)
                    kind = "ticket-granting service ticket" if m.msg_type == KRB_TGS_REP else "ticket-granting ticket"
                    out.append(self.finding(
                        code="KERBEROS_PRINCIPAL_INVENTORY",
                        title=f"Kerberos principal {principal} obtained a {kind} for {service}",
                        severity="info", confidence="high",
                        summary=f"Principal {principal} in realm {m.realm or 'unknown'} received a {kind} for "
                        f"{service}. This is the inventory of who authenticates to which realm and uses which "
                        "service on this network.",
                        scope=scope, flow_key=m.key, subjects=subjects(m.key),
                        evidence=[ev(m.frame, "kerberos.CNameString", principal),
                                  ev(m.frame, "kerberos.SNameString", service)],
                        remediation="Confirm this principal is expected to use this service, and that the account is "
                        "not a shared or generic one. If the principal is not yours, the capture carries traffic "
                        "for an account you do not control and the host should be looked at.",
                        references=[RFC_4120], tags=["kerberos", "inventory"]))
                if m.msg_type == KRB_TGS_REP and principal not in authenticated:
                    scope = f"no-as|{principal}|{service}"
                    if scope not in seen:
                        seen.add(scope)
                        out.append(self.finding(
                            code="KERBEROS_TGS_WITHOUT_AS",
                            title=f"Kerberos service ticket for {service} issued to {principal} with no AS exchange",
                            severity="medium", confidence="low",
                            summary=f"The KDC issued a service ticket for {service} to {principal}, but no AS request "
                            f"or reply for that principal appears anywhere in this capture. Either the initial "
                            "authentication happened before the capture started, or the ticket was obtained some "
                            "other way: delegation (S4U2Self or constrained delegation) or a ticket taken from "
                            "another host.",
                            scope=scope, flow_key=m.key, subjects=subjects(m.key),
                            evidence=[ev(m.frame, "kerberos.SNameString", service),
                                      ev(m.frame, "kerberos.CNameString", principal)],
                            remediation="Check whether the AS exchange happened before this capture started. If it "
                            "did not, review S4U2Self and constrained delegation on the account and on the KDC, and "
                            "confirm the client address that asked for the ticket is the one you expect.",
                            references=[RFC_4120, ATTACK_DELEGATION], tags=["kerberos", "delegation"]))
            elif not principal and m.realm:
                scope = f"anonymous|{m.realm}|{service}"
                if scope not in seen:
                    seen.add(scope)
                    out.append(self.finding(
                        code="KERBEROS_ANONYMOUS_REPLY",
                        title=f"Kerberos reply in realm {m.realm} names no client principal",
                        severity="low", confidence="high",
                        summary=f"A Kerberos reply in realm {m.realm} carries no client principal: the KDC answered "
                        "an anonymous request and issued a ticket that names nobody. Anonymous PKINIT lets a "
                        "client obtain a ticket without proving who it is, which turns the realm into an "
                        "unauthenticated entry point.",
                        scope=scope, flow_key=m.key, subjects=subjects(m.key),
                        evidence=[ev(m.frame, "kerberos.realm", m.realm)],
                        remediation="Turn anonymous PKINIT off for the realm and require pre-authentication on the "
                        "affected accounts (Active Directory: 'Network security: Configurable encryption types' "
                        "on the KDC, and 'Do not require Kerberos preauthentication' cleared on the accounts).",
                        references=[RFC_6113], tags=["kerberos", "pkinit"]))
        return out
