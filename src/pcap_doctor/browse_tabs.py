"""Host, file and credential views over a built ``CaptureIndex`` (issue #252).

Read-only: every row is copied out of the index, so no tshark pass runs here. Credentials never carry
secret material: HTTP auth comes through ``redact_auth`` and Telnet logins keep only the password length,
the same rule the index applies when it builds them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from .index import CaptureIndex

TABS = ("hosts", "files", "credentials")


@dataclass(frozen=True)
class HostRow:
    ip: str
    mac: str | None
    vendor: str | None
    hostname: str | None
    os_guess: str | None
    roles: tuple[str, ...]
    flows: int
    bytes: int


@dataclass(frozen=True)
class FileRow:
    frame: int
    source: str  # http | smb
    name: str
    flow: str


@dataclass(frozen=True)
class CredentialRow:
    frame: int
    source: str  # http | telnet | smb
    user: str | None
    secret: str  # already redacted: an auth preview, a length, or ""
    flow: str


def hosts(index: CaptureIndex) -> list[HostRow]:
    rows = [
        HostRow(h.ip, h.mac, h.vendor, h.hostname, h.os_guess, tuple(h.roles), h.flows, h.bytes)
        for h in index.hosts.values()
    ]
    return sorted(rows, key=lambda r: -r.bytes)


def files(index: CaptureIndex) -> list[FileRow]:
    rows: list[FileRow] = []
    for exch in index.http:
        rows.extend(FileRow(exch.frame, "http", name, exch.key) for name in exch.download_names)
    for op in index.smb:
        if op.filename and op.command in ("CREATE", "NT_CREATE_ANDX"):
            rows.append(FileRow(op.frame, "smb", op.filename, op.key))
    return sorted(rows, key=lambda r: r.frame)


def credentials(index: CaptureIndex) -> list[CredentialRow]:
    rows: list[CredentialRow] = []
    for exch in index.http:
        if exch.auth_present:
            rows.append(CredentialRow(exch.frame, "http", None, exch.auth_value_preview or "", exch.key))
    for login in index.telnet_logins:
        rows.append(
            CredentialRow(login.user_frame or login.password_frame, "telnet", login.user,
                          f"password of {login.password_length} chars", login.key)
        )
    for op in index.smb:
        if op.user is not None and not op.anonymous and not op.response and op.command == "SESSION_SETUP":
            rows.append(CredentialRow(op.frame, "smb", op.user, "", op.key))
    return sorted(rows, key=lambda r: r.frame)

T = TypeVar("T")


def narrow(rows: Sequence[T], text: str | None) -> list[T]:
    """Keep the rows with ``text`` in any column, ignoring case. A read-only display filter.

    Every field of the row dataclasses is a column its tab shows, so a match is always visible in the table.
    """
    if not text:
        return list(rows)
    needle = text.lower()
    return [r for r in rows if any(needle in str(v).lower() for v in vars(r).values())]
