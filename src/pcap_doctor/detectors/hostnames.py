"""D14 -- interesting hostnames (#239).

Parity with Zeek's ``Interesting_Hostname_Login`` and ``External_Name``: flag hostnames whose first label looks like a login, admin or sign-in panel that an attacker (or a careless browser history) could reach, wherever the hostname is visible in cleartext:

* DNS queries (``dns.qry.name``),
* TLS Server Name Indication (``tls.handshake.extensions_server_name``),
* HTTP ``Host`` headers (``http.host``).

The detector reports the *name*, never credentials. A boring name such as ``www`` or ``mail`` is silent; only labels that look like an admin/login surface are flagged. Confidence is ``medium``: the match is a syntactic heuristic against a label the capture does not confirm, and the same surface can be reached over TLS once the name is known.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev

#: First labels that look like a login / admin / sign-in surface. Zeek's Interesting_Hostname_Login
#: uses a similar, advisory word list; this is a deliberate, small allow-list, not regex over untrusted text.
INTERESTING_LABELS = frozenset(
    {
        "admin", "administrator", "admin-panel", "admin-console", "admin-login",
        "login", "signin", "sign-in", "signup", "sign-up", "register",
        "wp-login", "wp-admin", "cpanel", "webmail", "mailadmin",
        "oauth", "sso", "idp",
    }
)


def first_label(name: str) -> str:
    """The leftmost label of a hostname, lower-cased; empty for a bare IP or junk."""
    if not name:
        return ""
    head = name.split(".", 1)[0]
    return head.lower()


class HostnamesDetector(Detector):
    name: ClassVar[str] = "d14.hostnames"
    title: ClassVar[str] = "Interesting hostname lookup"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "dns"
    description: ClassVar[str] = (
        "Flags hostnames with a login/admin/sign-in-style first label seen in DNS queries, "
        "TLS SNI and HTTP Host headers, where they reveal a sensitive surface to an on-path observer."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        # Group every observation of a hostname across all surfaces so each name
        # produces one stable finding with all its evidence. The scope is the name
        # itself, so Finding.id is stable across runs even if surfaces change.
        grouped: dict[str, list[tuple[int, str, str | None, list[str]]]] = {}
        for name, frame, field, flow_key, subjects in self._collect(index):
            if not name:
                continue
            entry = (frame, field, flow_key, subjects)
            grouped.setdefault(name, []).append(entry)
        for name in sorted(grouped):
            label = first_label(name)
            if label not in INTERESTING_LABELS:
                continue
            observations = grouped[name]
            evidence = [ev(o[0], o[1], name) for o in observations]
            flow_keys = {o[2] for o in observations if o[2]}
            findings.append(
                self.finding(
                    code="INTERESTING_HOSTNAME",
                    title=f"Interesting hostname exposed: {name}",
                    severity="low",
                    confidence="medium",
                    summary=(
                        f"The hostname {name} has a first label ({label}) that marks an admin/login/"
                        "sign-in surface. It was observed in cleartext in this capture, so any on-path "
                        "observer can learn the exact panel address and target it directly."
                    ),
                    scope=f"hostname|{name}",
                    flow_key=next(iter(flow_keys), None),
                    subjects=[name],
                    evidence=evidence,
                    remediation=(
                        "Move sensitive panels behind a private DNS / VPN name and do not expose them "
                        "in cleartext DNS, SNI or Host headers; prefer encrypted DNS (DoT/DoH) and "
                        "consider ECH so SNI itself is hidden."
                    ),
                    references=["RFC 9001", "RFC 8484", "CWE-200"],
                    tags=["dns", "tls", "http", "discovery", "heuristic"],
                )
            )
        return findings

    def _collect(self, index: CaptureIndex) -> list[tuple[str, int, str, str | None, list[str]]]:
        """Gather (hostname, frame, field, flow_key, subjects) across DNS, TLS SNI and HTTP Host."""
        out: list[tuple[str, int, str, str | None, list[str]]] = []
        # DNS queries.
        for q in index.dns:
            if q.is_response or not q.name:
                continue
            out.append((q.name, q.frame, "dns.qry.name", q.key, [q.name]))
        # TLS SNI.
        for session in index.tls.values():
            sni = session.sni
            if not sni:
                continue
            frame = session.frames[0] if session.frames else 0
            out.append((sni, frame, "tls.handshake.extensions_server_name", session.key, [sni]))
        # HTTP Host headers (cleartext HTTP; HTTPS Host is inside the tunnel and unseen here).
        for exch in index.http:
            if not exch.is_encrypted and exch.host:
                out.append((exch.host, exch.frame, "http.host", exch.key, [exch.host]))
        return out
