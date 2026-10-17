"""Local GeoIP / ASN lookup from a CSV range file the user supplies (issue #237).

Opt-in and offline: nothing is fetched. The file has the header ``network,asn,as_name,country`` and one CIDR per row;
``#`` comment lines and blank lines are ignored. Networks of one IP version must not overlap, which keeps a lookup
to one binary search. A MaxMind .mmdb would need a binary reader; a CSV needs none and no new dependency.
"""

from __future__ import annotations

import csv
import ipaddress
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

_HEADER = ["network", "asn", "as_name", "country"]


class GeoIpError(ValueError):  # ValueError, not PolicyError: policy imports index, which imports this module
    """A GeoIP database that cannot be read, or holds a malformed or overlapping row."""


@dataclass(frozen=True)
class GeoRecord:
    asn: int
    as_name: str
    country: str


class GeoIpDb:
    def __init__(self, rows: list[tuple[int, int, int, GeoRecord]]) -> None:
        # (ip version, first address, last address, record), sorted per version so a lookup is one bisect
        self._tables: dict[int, tuple[list[int], list[int], list[GeoRecord]]] = {4: ([], [], []), 6: ([], [], [])}
        for version, first, last, record in sorted(rows, key=lambda r: (r[0], r[1])):
            starts, ends, records = self._tables[version]
            if ends and first <= ends[-1]:
                raise GeoIpError(f"GeoIP networks overlap at {ipaddress.ip_address(first)}; keep them disjoint")
            starts.append(first)
            ends.append(last)
            records.append(record)

    def lookup(self, ip: str) -> GeoRecord | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        starts, ends, records = self._tables[addr.version]
        i = bisect_right(starts, int(addr)) - 1
        if i >= 0 and int(addr) <= ends[i]:
            return records[i]
        return None


def load_geoip(path: Path) -> GeoIpDb:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise GeoIpError(f"cannot read GeoIP database {path}: {exc}") from exc
    rows: list[tuple[int, int, int, GeoRecord]] = []
    seen_header = False
    for lineno, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = next(csv.reader([raw]))
        if not seen_header:
            if [f.strip() for f in fields] != _HEADER:
                raise GeoIpError(f"GeoIP database {path}: expected header {','.join(_HEADER)}")
            seen_header = True
            continue
        if len(fields) != 4:
            raise GeoIpError(f"GeoIP database {path} line {lineno}: expected 4 fields, got {len(fields)}")
        try:
            net = ipaddress.ip_network(fields[0].strip(), strict=False)
        except ValueError as exc:
            raise GeoIpError(f"GeoIP database {path} line {lineno}: bad network {fields[0]!r}") from exc
        try:
            asn = int(fields[1])
        except ValueError as exc:
            raise GeoIpError(f"GeoIP database {path} line {lineno}: asn must be an integer") from exc
        record = GeoRecord(asn=asn, as_name=fields[2].strip(), country=fields[3].strip())
        rows.append((net.version, int(net.network_address), int(net.broadcast_address), record))
    if not seen_header:
        raise GeoIpError(f"GeoIP database {path} is empty; expected header {','.join(_HEADER)}")
    return GeoIpDb(rows)
