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

FIXTURES = Path(__file__).parent / "fixtures"

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


@requires_tshark
def test_host_table_shows_asn_only_when_geoip_given(tmp_path: Path) -> None:
    """Without --geoip-db the flows report is byte-identical to the committed golden; with it, an ASN column appears."""
    from pcap_doctor.pipeline import analyze

    golden = FIXTURES / "brute_force.pf-report" / "01-flows.md"
    plain = analyze(fixture("brute_force.pcap"), tmp_path / "plain", use_cache=False).artifacts
    plain_flows = next(a for a in plain if Path(a).name == "01-flows.md")
    assert Path(plain_flows).read_bytes() == golden.read_bytes()

    db = load_geoip(_db(tmp_path, "network,asn,as_name,country\n10.0.0.0/8,64496,SCRATCH-NET,ZZ\n"))
    geo = analyze(fixture("brute_force.pcap"), tmp_path / "geo", use_cache=False, geoip=db).artifacts
    text = Path(next(a for a in geo if Path(a).name == "01-flows.md")).read_text()
    assert "| ASN / country |" in text
    assert "AS64496 SCRATCH-NET, ZZ" in text
