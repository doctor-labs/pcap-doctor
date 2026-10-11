"""Password-guessing counts per client, server and service (issue #207)."""

from __future__ import annotations

from conftest import fixture, requires_tshark

ATTACKER, VICTIM, QUIET = "10.5.0.66", "10.5.0.20", "10.5.0.11"


@requires_tshark
def test_each_guessed_service_is_one_finding_and_the_mistyping_user_is_not(analyze_capture) -> None:
    found = [f for f in analyze_capture(fixture("brute_force.pcap")).report.findings if f.code == "BRUTE_FORCE_SUSPECTED"]
    assert sorted(f.title for f in found) == [
        f"10 failed SMB logins from {ATTACKER} to {VICTIM}",
        f"12 failed HTTP logins from {ATTACKER} to {VICTIM}",
        f"20 failed FTP logins from {ATTACKER} to {VICTIM}",
    ]
    for f in found:
        assert f.subjects == [ATTACKER, VICTIM]
        assert f.severity == "high" and f.confidence == "medium"
        assert 1 <= len(f.evidence) <= 5 and all(e.frame > 0 and e.value for e in f.evidence)
        assert QUIET not in f.subjects
    fields = {f.title.split()[2]: {e.field for e in f.evidence} for f in found}
    assert fields == {"FTP": {"ftp.response.code"}, "HTTP": {"http.response.code"}, "SMB": {"smb2.nt_status"}}


@requires_tshark
def test_findings_are_stable_across_runs(analyze_capture) -> None:
    from pcap_doctor.pipeline import analyze

    first = {f.id for f in analyze_capture(fixture("brute_force.pcap")).report.findings}
    again = {f.id for f in analyze(fixture("brute_force.pcap")).report.findings}
    assert first == again
