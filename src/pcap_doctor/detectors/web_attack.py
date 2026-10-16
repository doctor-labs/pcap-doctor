"""D14 -- Web attacks in HTTP request URIs: SQLi, XSS, LFI, path traversal, OS command injection (#233)."""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import unquote

from ..index import CaptureIndex
from ..models import Finding, Severity
from .base import Detector, ev

#: (pattern, human label)
SQLI_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"""('|")\s*or\s+('|")?\d+\1?\s*=\s*('|")?\d+""", re.IGNORECASE),
        "OR-based boolean SQL injection",
    ),
    (re.compile(r"(--|#)\s*$"), "SQL comment terminator"),
    (re.compile(r"\bunion\b\s+\bselect\b", re.IGNORECASE), "UNION SELECT injection"),
    (re.compile(r"\bor\b\s+1\s*=\s*1", re.IGNORECASE), "OR 1=1 injection"),
)

XSS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<\s*script\b", re.IGNORECASE), "<script> tag"),
    (re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE), "</script> tag"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: URI"),
    (re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE), "inline event handler"),
)

LFI_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"php\s*:\s*//\s*filter", re.IGNORECASE), "PHP filter wrapper inclusion"),
    (re.compile(r"\.\./\.\./etc/passwd", re.IGNORECASE), "../etc/passwd traversal"),
    (re.compile(r"(^|[=/])\.\./\.\./etc/", re.IGNORECASE), "etc/ traversal"),
    (re.compile(r"file\s*://", re.IGNORECASE), "file:// wrapper inclusion"),
    (re.compile(r"/etc/(passwd|shadow)\b", re.IGNORECASE), "/etc/passwd or /etc/shadow reference"),
)

TRAVERSAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.\./\.\./"), "path traversal (multiple ../)"),
)

COMMAND_INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"[;|&]\s*(cat|ls|id|whoami|uname|wget|curl|nc|sh|bash)\b", re.IGNORECASE),
        "command chaining injection",
    ),
    (re.compile(r"\$\(.+\)"), "command substitution $(...)"),
    (re.compile(r"`[^`]+`"), "backtick command substitution"),
    (re.compile(r"\|\s*sh\b", re.IGNORECASE), "pipe to shell"),
)

#: family -> (patterns, severity)
SIGNATURES: dict[str, tuple[tuple[tuple[re.Pattern[str], str], ...], Severity]] = {
    "SQLI": (SQLI_PATTERNS, "high"),
    "XSS": (XSS_PATTERNS, "medium"),
    "LFI": (LFI_PATTERNS, "medium"),
    "TRAVERSAL": (TRAVERSAL_PATTERNS, "low"),
    "COMMAND_INJECTION": (COMMAND_INJECTION_PATTERNS, "high"),
}

#: All codes this detector can emit (kept as literals so test_rules_catalog can see them).
_CODES = (
    "HTTP_WEB_ATTACK_SQLI",
    "HTTP_WEB_ATTACK_XSS",
    "HTTP_WEB_ATTACK_LFI",
    "HTTP_WEB_ATTACK_TRAVERSAL",
    "HTTP_WEB_ATTACK_COMMAND_INJECTION",
)

#: family -> remediation text
REMEDIATION: dict[str, str] = {
    "SQLI": "Parameterise all SQL via prepared statements / ORM bindings, validate input against an allow-list, and reject raw quotes in parameters.",
    "XSS": "Context-encode all user input on output, use a strict Content-Security-Policy, and set the HttpOnly and Secure flags on cookies.",
    "LFI": "Deny user-controlled path segments; map requests to a fixed allow-list of files instead of including from user input.",
    "TRAVERSAL": "Normalise and canonicalise paths, reject or strip `..` segments, and serve files only from a fixed root directory.",
    "COMMAND_INJECTION": "Avoid calling a shell with user input; pass arguments as a list to exec-family APIs and reject shell metacharacters (; | & $ `).",
}


class WebAttackDetector(Detector):
    name: ClassVar[str] = "d16.web_attack"
    title: ClassVar[str] = "Web attacks in HTTP request URIs"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "Cleartext"
    description: ClassVar[str] = (
        "Detects SQL injection, XSS, local file inclusion, path traversal and OS command injection in HTTP request URIs."
    )
    enabled: ClassVar[bool] = True

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for exch in index.http:
            if not exch.uri:
                continue
            raw = exch.uri
            try:
                decoded = unquote(raw)
            except Exception:
                decoded = raw
            hay = (raw + "\n" + decoded).lower()
            flow = index.flows.get(exch.key)
            if flow is not None:
                # HTTP server is the lower-numeric-port endpoint; client is the other side.
                if flow.port_a <= flow.port_b:
                    server, client = flow.endpoint_a, flow.endpoint_b
                else:
                    server, client = flow.endpoint_b, flow.endpoint_a
            else:
                server, client = "", ""

            for family, (patterns, severity) in SIGNATURES.items():
                for pattern, label in patterns:
                    match = pattern.search(hay)
                    if match is None:
                        continue
                    matched_snippet = match.group(0)[:120]
                    findings.append(
                        self.finding(
                            code=f"HTTP_WEB_ATTACK_{family}",
                            title=f"Web attack in HTTP request: {label}",
                            severity=severity,
                            confidence="high",
                            summary=f"Client {client} sent an HTTP request with a {family} payload to {server}: {matched_snippet}",
                            scope=f"{family}:{exch.key}",
                            flow_key=exch.key,
                            subjects=[client, server],
                            evidence=[ev(exch.frame, "http.request.uri", matched_snippet)],
                            remediation=REMEDIATION[family],
                            references=["OWASP Web Security Testing Guide"],
                            tags=["http", "web-attack", family.lower()],
                        )
                    )
                    break  # one finding per (exchange, family)
        return findings
