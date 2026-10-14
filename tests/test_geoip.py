"""Local GeoIP / ASN enrichment of hosts (issue #237).

The database is a CSV the user supplies (no network): header ``network,asn,as_name,country``, one CIDR per row.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.geoip import GeoIpError, load_geoip
from pcap_doctor.index import IndexBuilder
from pcap_doctor.tshark import TsharkRunner

DB = "network,asn,as_name,country\n10.40.0.0/24,64500,EXAMPLE-NET,US\n2001:db8::/32,64501,V6-NET,DE\n"


def _db(tmp_path: Path, text: str = DB) -> Path:
    path = tmp_path / "geo.csv"
    path.write_text(text)
    return path


def test_lookup_hits_covered_ranges_and_misses_the_rest(tmp_path: Path) -> None:
    db = load_geoip(_db(tmp_path))
    assert db.lookup("10.40.0.7") is not None
    assert db.lookup("10.40.0.7").asn == 64500  # type: ignore[union-attr]
    assert db.lookup("2001:db8::1").country == "DE"  # type: ignore[union-attr]
    assert db.lookup("10.41.0.1") is None
    assert db.lookup("not-an-ip") is None


def test_malformed_database_is_refused_not_skipped(tmp_path: Path) -> None:
    with pytest.raises(GeoIpError, match="line 2"):
        load_geoip(_db(tmp_path, "network,asn,as_name,country\n10.0.0.0/8,notanumber,X,US\n"))
    with pytest.raises(GeoIpError, match="overlap"):
        load_geoip(_db(tmp_path, "network,asn,as_name,country\n10.0.0.0/8,1,A,US\n10.1.0.0/16,2,B,US\n"))


@requires_tshark
def test_index_sets_asn_note_on_covered_hosts(tmp_path: Path) -> None:
    db = load_geoip(_db(tmp_path))
    index = IndexBuilder(TsharkRunner(fixture("devices.pcap"), use_cache=False), geoip=db).build()
    by_ip = {h.ip: h for h in index.hosts.values()}
    assert by_ip["10.40.0.1"].asn_note == "AS64500 EXAMPLE-NET, US"


@requires_tshark
def test_no_database_leaves_asn_note_unset() -> None:
    index = IndexBuilder(TsharkRunner(fixture("devices.pcap"), use_cache=False)).build()
    assert all(h.asn_note is None for h in index.hosts.values())
