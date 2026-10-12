"""D14 -- RADIUS credential exposure.

RADIUS Access-Request packets carry a username in cleartext (User-Name AVP,
type 1) and the User-Password AVP (type 2) is encrypted only with the shared
secret, not with TLS. Anyone who captures the shared secret — or anyone who
reads the RADIUS log — sees the username. A CLEARTEXT_CREDENTIAL finding is
raised for every username observed.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..logs import log_rows
from ..models import Finding, flow_key
from .base import Detector, ev


class RadiusDetector(Detector):
    name: ClassVar[str] = "d18.radius"
    title: ClassVar[str] = "RADIUS credential exposure"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "cleartext"
    description: ClassVar[str] = (
        "Reports RADIUS Access-Request exchanges where a User-Name is sent in cleartext "
        "(User-Password is encrypted with the shared secret, not TLS, so the username still leaks)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for row in log_rows(index, "radius"):
            username = row.get("username")
            if not username:
                continue
            fkey = flow_key("udp", row.get("id.orig_h", ""), row.get("id.orig_p", 0),
                            row.get("id.resp_h", ""), row.get("id.resp_p", 0))
            scope = f"radius|{username}|{row.get('id.orig_h', '')}|{row.get('id.resp_h', '')}"
            out.append(
                self.finding(
                    code="CLEARTEXT_CREDENTIAL",
                    title=f"RADIUS username '{username}' sent in cleartext",
                    severity="high",
                    confidence="high",
                    summary=(
                        f"RADIUS Access-Request on {row.get('id.orig_h', '?')}"
                        f":{row.get('id.orig_p', '?')} -> {row.get('id.resp_h', '?')}"
                        f":{row.get('id.resp_p', '?')}"
                        f" carries User-Name='{username}'. User-Password is encrypted with the "
                        "RADIUS shared secret (not TLS), so the username is exposed to anyone who "
                        "captures the shared secret or this log."
                    ),
                    scope=scope,
                    flow_key=fkey,
                    subjects=[row.get("id.orig_h") or "", row.get("id.resp_h") or ""],
                    evidence=[ev(row.get("frame") or 0, "radius.User_Name", username)],
                    remediation=(
                        "Rotate the shared secret, migrate to RADIUS over TLS / RadSec, and "
                        "rotate the affected user credentials."
                    ),
                    references=["RFC 2865", "CWE-319"],
                    tags=["radius", "cleartext", "credential"],
                )
            )
        return out
