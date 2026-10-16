"""RADIUS dissection and credential extraction (issue #222).

Ground truth verified on this machine with tshark 4.6.6 and zeek 8.2.0 against
tests/fixtures/radius_logins.pcap:

    tshark -r radius_logins.pcap
      1 10.90.0.1 -> 10.90.0.2 RADIUS 121 Access-Request id=7
      2 10.90.0.1 -> 10.90.0.2 RADIUS  93 Access-Request id=9
      3 10.90.0.2 -> 10.90.0.1 RADIUS  62 Access-Reject   id=7

    tshark -T fields -e frame.number -e radius.code -e radius.id \
                     -e radius.User_Name -e radius.Calling_Station_Id
      1|1|7|alice|00-11-22-33-44-55
      2|1|9|bob|00-11-22-33-44-66
      3|3|7||

    zeek -r radius_logins.pcap  ->  radius.log
      ... 10.90.0.1 51234 10.90.0.2 1812 alice 00-11-22-33-44-55 ... failed

Only the version-stable fields are asserted. CHAP-Password is not exercised:
tshark 4.6.6 reports AVP length 20 as "[wrong length for CHAP-Password]" and
never populates radius.CHAP_Password, so asserting on it would pin a quirk of
this dissector build rather than the protocol.
"""

from __future__ import annotations

from pathlib import Path

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.logs import LOG_NAMES


def _tsv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    header: list[str] = []
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("#fields"):
            header = line.split("\t")[1:]
        elif not line.startswith("#"):
            rows.append(dict(zip(header, line.split("\t"), strict=True)))
    return header, rows


@requires_tshark
def test_radius_is_an_exported_log_name() -> None:
    assert "radius" in LOG_NAMES


@requires_tshark
def test_radius_log_captures_the_observed_exchanges(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "radius"
    result = cli_runner.invoke(app, ["logs", str(fixture("radius_logins.pcap")), "-o", str(out), "--only", "radius"])
    assert result.exit_code == 0, result.output

    header, rows = _tsv(out / "radius.log")
    by_user = {r["username"]: r for r in rows if r.get("username") not in (None, "", "-")}

    # Both Access-Requests are seen. Zeek 8.2.0 agrees on the first row's shape.
    assert set(by_user) == {"alice", "bob"}

    alice = by_user["alice"]
    assert alice["id.orig_h"] == "10.90.0.1"
    assert alice["id.orig_p"] == "51234"
    assert alice["id.resp_h"] == "10.90.0.2"
    assert alice["id.resp_p"] == "1812"
    assert alice["mac"] == "00-11-22-33-44-55"
    # Zeek writes result="failed" for an Access-Reject that shares a request id (7).
    assert alice["result"] == "failed"

    assert by_user["bob"]["mac"] == "00-11-22-33-44-66"
    assert "username" in header and "mac" in header


@requires_tshark
def test_radius_never_writes_the_shared_secret_or_tunnel_password(cli_runner, tmp_path, cache_dir) -> None:
    """RADIUS User-Password is encrypted with a shared secret (RFC 2865 s5.2).

    Without that secret the plaintext is unrecoverable, so the log must carry the
    ciphertext (or nothing) and must never claim the decoded secret.
    """
    out = tmp_path / "radius-secrets"
    assert cli_runner.invoke(app, ["logs", str(fixture("radius_logins.pcap")), "-o", str(out), "--only", "radius"]).exit_code == 0
    text = (out / "radius.log").read_text()
    assert "s3cr3t-radius" not in text, "the shared secret must not be recoverable from the log"
    assert "tunnel-secret" not in text, "Tunnel-Password must not be written as plaintext"


@requires_tshark
def test_radius_exchange_raises_a_credential_finding(analyze_capture) -> None:
    """A RADIUS exchange carrying User-Password must raise a finding naming the users."""
    findings = [f for f in analyze_capture(fixture("radius_logins.pcap")).report.findings
                if "radius" in f.title.lower()]
    assert findings, "expected a finding naming the RADIUS credentials"
    joined = " ".join(f.title + " " + f.summary for f in findings)
    assert "alice" in joined, joined


def test_radius_log_is_queryable_and_typos_exit_2(cli_runner, cache_dir) -> None:
    pcap = str(fixture("radius_logins.pcap"))
    ok = cli_runner.invoke(app, ["query", pcap, 'username == "alice"', "-s", "log:radius", "--json"])
    assert ok.exit_code == 0, ok.output
    assert cli_runner.invoke(app, ["logs", pcap, "--only", "nope"]).exit_code == 2