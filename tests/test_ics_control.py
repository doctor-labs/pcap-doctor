"""D15 ics_control: cleartext write and control commands on Modbus, DNP3, S7comm and IEC 60870-5-104 (#206)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


def _by_source(result) -> dict[tuple[str, str], object]:
    # Finding.id hashes the scope; the readable key is the protocol tag plus source and destination endpoint.
    found = [f for f in result.report.findings if f.code == "ICS_CONTROL_COMMAND"]
    return {(f.tags[1], f.subjects[1]): f for f in found}


@requires_tshark
def test_one_finding_per_commanding_source_destination_and_protocol(analyze_capture) -> None:
    result = analyze_capture(fixture("ics_control.pcap"))
    assert sorted(_by_source(result)) == [
        ("dnp3", "10.9.0.30:20000"),
        ("iec104", "10.9.0.50:2404"),
        ("modbus", "10.9.0.20:502"),
        ("s7comm", "10.9.0.40:102"),
    ]


@requires_tshark
def test_reads_and_replies_are_not_flagged(analyze_capture) -> None:
    found = _by_source(analyze_capture(fixture("ics_control.pcap")))
    assert [e.value for e in found[("modbus", "10.9.0.20:502")].evidence] == ["WRITE_SINGLE_REGISTER"]
    assert found[("modbus", "10.9.0.20:502")].evidence[0].frame > 0
    assert [e.value for e in found[("iec104", "10.9.0.50:2404")].evidence] == ["C_SC_NA_1"]
    assert [e.value for e in found[("dnp3", "10.9.0.30:20000")].evidence] == ["OPERATE"]
    assert [e.value for e in found[("s7comm", "10.9.0.40:102")].evidence] == ["Write Var"]
