"""D15 -- vulnerable software versions announced in banners and headers (#235).

Parity with Zeek's ``Vulnerable_Version`` idea: the software inventory (HTTP ``Server``, HTTP
``User-Agent`` and SSH banners, as in ``software.log``) is matched against a short, curated list of
versions with a published vulnerability. The version string is what the peer announced, so the
finding is a heuristic: confidence is ``medium`` and the summary says so.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..index import CaptureIndex
from ..logs import _parse_http_version, _parse_ssh_version
from ..models import Finding, Flow
from .base import Detector, ev

Version = tuple[int, ...]

#: (software name as logged, first affected version or None, first *unaffected* version or None, CVE).
#: Bounds are half-open: affected when ``first <= version < before``. Entries are deliberately few and
#: each is a well-known, exactly-bounded vulnerability; extend it with a reference, not a guess.
VULNERABLE: tuple[tuple[str, Version | None, Version | None, str], ...] = (
    ("Apache", (2, 4, 49), (2, 4, 50), "CVE-2021-41773"),
    ("Apache", (2, 4, 50), (2, 4, 51), "CVE-2021-42013"),
    ("OpenSSH", None, (7, 4), "CVE-2016-10012"),
    ("vsftpd", (2, 3, 4), (2, 3, 5), "CVE-2011-2523"),
    ("Exim", (4, 87), (4, 92), "CVE-2019-10149"),
    ("ProFTPD", (1, 3, 5), (1, 3, 6), "CVE-2015-3306"),
    ("Microsoft-IIS", (6, 0), (6, 1), "CVE-2017-7269"),
)

_NUMERIC = re.compile(r"\d+(?:\.\d+)*")


def parse_version(text: str | None) -> Version | None:
    """The leading dotted-numeric part of a version string: ``7.4p1`` -> (7, 4); no digits -> None."""
    if not text:
        return None
    match = _NUMERIC.match(text)
    return tuple(int(part) for part in match.group(0).split(".")) if match else None


def vulnerable_cve(name: str | None, version: str | None) -> str | None:
    """The CVE for a logged name/version that falls in a known-vulnerable range, else None."""
    parsed = parse_version(version)
    if not name or parsed is None:
        return None
    for sw, first_bad, before, cve in VULNERABLE:
        if sw.lower() != name.lower():
            continue
        if first_bad is not None and parsed < first_bad:
            continue
        if before is not None and parsed >= before:
            continue
        return cve
    return None


class SoftwareVulnsDetector(Detector):
    name: ClassVar[str] = "d22.software_vulns"
    title: ClassVar[str] = "Vulnerable software version"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "services"
    description: ClassVar[str] = (
        "Software and versions announced in HTTP Server/User-Agent headers and SSH banners that match "
        "a short list of known-vulnerable version ranges (Zeek Vulnerable_Version parity)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        # Reads only what the index already holds (no extra tshark pass). The announcing side of a
        # flow is the lower port, which is the service side for every banner this detector reads.
        # One finding per (announcing host, software, version); every announcement is evidence.
        grouped: dict[tuple[str, str, str], list[tuple[int, str, str]]] = {}
        for exch in index.http:
            if exch.is_encrypted:
                continue
            flow = index.flows.get(exch.key)
            if flow is None:
                continue
            server_ip, client_ip = _sides(flow)
            if exch.server:
                name, version = _parse_http_version(exch.server)
                if vulnerable_cve(name, version):
                    grouped.setdefault((server_ip, name or "", version or ""), []).append(
                        (exch.frame, "http.server", exch.server))
            if exch.user_agent:
                name, version = _parse_http_version(exch.user_agent)
                if vulnerable_cve(name, version):
                    grouped.setdefault((client_ip, name or "", version or ""), []).append(
                        (exch.frame, "http.user_agent", exch.user_agent))
        for session in index.ssh:
            flow = index.flows.get(session.key)
            if flow is None or not session.server_version:
                continue
            server_ip, _ = _sides(flow)
            name, version = _parse_ssh_version(session.server_version)
            if vulnerable_cve(name, version):
                grouped.setdefault((server_ip, name or "", version or ""), []).append(
                    (session.frame, "ssh.protocol", session.server_version))
        findings: list[Finding] = []
        for (src, name, version) in sorted(grouped):
            cve = vulnerable_cve(name, version) or ""
            observations = grouped[(src, name, version)]
            findings.append(
                self.finding(
                    code="SERVICE_VULNERABLE_VERSION",
                    title=f"Vulnerable software announced: {name} {version} from {src}",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{src} announces {name} {version} in a banner or header. That version falls in a "
                        f"range with a published vulnerability ({cve}). The version is self-reported, so "
                        "the match says the announced build is affected, not that the service is exploitable "
                        "from this capture; vendor backports can also fix a version string that looks old."
                    ),
                    scope=f"software|{src}|{name}|{version}",
                    flow_key=None,
                    subjects=[src],
                    evidence=[ev(frame, field, raw) for frame, field, raw in observations],
                    remediation=(
                        f"Upgrade {name} to a release that is not in the affected range for {cve}, or confirm "
                        "with the vendor that the installed build is patched. Remove or restrict the banner "
                        "where possible, and do not expose the service to untrusted networks until it is updated."
                    ),
                    references=[cve],
                    tags=["services", "version", "heuristic"],
                )
            )
        return findings


def _sides(flow: Flow) -> tuple[str, str]:
    """(service side, client side) of a flow: the endpoint on the lower port is the service."""
    if flow.port_a <= flow.port_b:
        return flow.endpoint_a, flow.endpoint_b
    return flow.endpoint_b, flow.endpoint_a
