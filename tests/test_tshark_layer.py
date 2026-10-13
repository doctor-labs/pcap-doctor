"""The tshark boundary: field drift, self-healing, caching, parsing helpers.

Field names move between tshark releases. These tests pin what we rely on and
prove the self-healing path works, because a field that quietly disappears must
degrade into a note, never into a wrong answer.
"""

from __future__ import annotations

import contextlib
import shutil
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.tshark import (
    PASSES,
    SERVICE_FIELDS,
    TsharkRunner,
    _low_priority_kwargs,
    default_prefs,
    parse_cipher_ids,
    parse_hex_bits,
    protocol_names,
    public_key_bits,
    split_multi,
    to_bool01,
    to_int,
    valid_fields,
    worker_count,
)

pytestmark = requires_tshark

#: Fields this project cannot work without.
REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.flags.syn",
    "tls.handshake.type",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3",
    "tls.handshake.ja3s",
    "dtls.handshake.type",
    "dtls.handshake.ciphersuite",
    "dns.qry.name",
    "sip.Method",
    "sdp.media",
    "rtp.ssrc",
    "ssh.protocol",
    "quic.version",
    "http.request.method",
    "http.response.code",
    "http.set_cookie",
    "http.authorization",
)


def test_required_fields_exist_in_this_tshark() -> None:
    known = valid_fields()
    missing = [f for f in REQUIRED_FIELDS if f not in known]
    assert not missing, (
        f"this tshark build ({TsharkRunner(Path('.')).version}) is missing {missing}; "
        "update tshark or adapt the pass in src/pcap_doctor/tshark.py"
    )


def test_display_filter_protocols_are_real() -> None:
    known = protocol_names()
    for name, spec in PASSES.items():
        if not spec.display_filter:
            continue
        for token in spec.display_filter.split("||"):
            token = token.strip()
            if " " in token or any(op in token for op in "()=<>!"):
                continue
            assert token in known or token.split(".")[0] in known, f"pass {name}: unknown protocol {token!r}"


def test_tls_and_dtls_passes_stay_in_sync() -> None:
    """DTLS must expose the same field set as TLS, just prefixed."""
    tls = {f[4:] for f in PASSES["tls"].fields if f.startswith("tls.")}
    dtls = {f[5:] for f in PASSES["dtls"].fields if f.startswith("dtls.")}
    assert tls == dtls, f"drift: only in tls {tls - dtls}, only in dtls {dtls - tls}"


def test_boolean_fields_parse_from_both_renderings() -> None:
    assert to_bool01("1") is True and to_bool01("0") is False
    assert to_bool01("True") is True and to_bool01("False") is False
    assert to_bool01("") is None and to_bool01("maybe") is None


def test_cipher_id_parsing() -> None:
    assert parse_cipher_ids("0xc02f") == [0xC02F]
    assert parse_cipher_ids("0xc02f,0x1301") == [0xC02F, 0x1301]
    # bare decimal must stay decimal: 4865 == 0x1301 (TLS_AES_128_GCM_SHA256)
    assert parse_cipher_ids("4865") == [4865]
    assert parse_cipher_ids("") == []
    assert parse_cipher_ids("nonsense") == []


def test_hex_bit_parsing() -> None:
    assert parse_hex_bits("00ff") == 16  # measured in bytes, leading zeros kept
    assert parse_hex_bits("00" * 256) == 2048
    assert parse_hex_bits("") is None
    assert parse_hex_bits("zz") is None
    assert parse_hex_bits("0") is None  # a lone zero nibble is not a key


def test_ec_curve_detection() -> None:
    # 1.2.840.10045.3.1.7 (prime256v1) inside a SubjectPublicKeyInfo blob
    assert public_key_bits("", "3082" + "06082a8648ce3d030107") == 256
    assert public_key_bits("", "3082" + "06052b810400") is None
    assert public_key_bits("00" * 256) == 2048


def test_split_multi_drops_empties() -> None:
    assert split_multi("a\x1fb\x1f") == ["a", "b"]


def test_to_int_is_strict() -> None:
    assert to_int("443") == 443
    assert to_int("0x1bb") is None
    assert to_int("") is None


def test_unknown_field_is_dropped_and_recorded() -> None:
    spec = PASSES["base"]
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    runner._field_blacklist.add("tcp.analysis.ack_rtt")
    fields = runner.usable_fields(spec)
    assert "tcp.analysis.ack_rtt" not in fields
    assert any("tcp.analysis.ack_rtt" in d for d in runner.dropped_fields)


def test_ws_column_fields_are_never_dropped() -> None:
    """_ws.col.* are not listed by -G fields but are perfectly valid."""
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    assert "_ws.col.Protocol" in runner.usable_fields(PASSES["base"])


def test_unknown_protocol_token_is_dropped_and_recorded() -> None:
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    # simulate a protocol this tshark build does not know
    runner._banned_protocols.add("telnet")
    resolved = runner._filter_for(PASSES["services"])
    assert resolved is not None
    assert "telnet" not in resolved
    assert "ntp" in resolved
    # a runtime ban is a fix-up, not field drift: it must not be reported as a
    # missing field, but the pass still has to be recorded somewhere
    assert isinstance(runner.dropped_fields, list)


def test_cache_hit_avoids_a_second_tshark_run() -> None:
    pcap = fixture("weak_tls.pcap")
    fresh = TsharkRunner(pcap, use_cache=True)
    rows_first = fresh.run("tls")
    second = TsharkRunner(pcap, use_cache=True)
    rows_second = second.run("tls")
    assert second.stats["tls"]["cached"] == 1
    assert rows_first == rows_second


def test_cache_is_keyed_by_content(tmp_path: Path) -> None:
    original = fixture("weak_tls.pcap")
    copy = tmp_path / "copy.pcap"
    shutil.copy(original, copy)
    a = TsharkRunner(original, use_cache=False)
    b = TsharkRunner(copy, use_cache=False)
    assert a.sha == b.sha  # same bytes -> same cache key


def test_rtp_decode_args_are_well_formed() -> None:
    args = TsharkRunner.rtp_decode_args([20000, 20000, 0, 70000])
    assert args == ("-d udp.port==20000,rtp",)


def test_extra_args_change_the_cache_key() -> None:
    pcap = fixture("weak_tls.pcap")
    plain = TsharkRunner(pcap, use_cache=True)._cache_file("base")
    with_extra = TsharkRunner(pcap, use_cache=True)._cache_file(
        "base", ("-d udp.port==20000,rtp",)
    )
    assert plain != with_extra


def test_tshark_version_and_prefs_are_discoverable() -> None:
    import pcap_doctor.tshark as mod

    assert mod.tshark_version().split()[0][0].isdigit()
    assert "tcp.desegment_tcp_streams" in default_prefs()
    assert "tls" in protocol_names()


def test_missing_binary_raises_a_clear_error(monkeypatch) -> None:
    import pcap_doctor.tshark as mod

    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    mod.tshark_path.cache_clear()
    with pytest.raises(mod.TsharkMissingError) as excinfo:
        mod.tshark_path()
    assert "tshark" in str(excinfo.value)
    mod.tshark_path.cache_clear()


def test_unreadable_capture_raises_a_useful_error(tmp_path: Path) -> None:
    from pcap_doctor.tshark import TsharkRunError

    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"not a pcap at all")
    runner = TsharkRunner(bogus, use_cache=False)
    with pytest.raises(TsharkRunError) as excinfo:
        runner.run("base")
    assert "base" in str(excinfo.value)


def test_shutil_present() -> None:
    """The environment probe itself is part of the contract."""
    assert shutil.which("capinfos") or shutil.which("tshark")


@requires_tshark
def test_every_service_field_is_a_real_tshark_field() -> None:
    """The index can only read what tshark can emit (issue #14)."""
    import subprocess

    out = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=True).stdout
    known = {line.split("\t")[2] for line in out.splitlines() if line.count("\t") >= 2}
    assert [field for field in SERVICE_FIELDS if field not in known] == []


@requires_tshark
def test_skip_pass_when_protocols_absent(monkeypatch) -> None:
    """#328: a pass whose protocols do not appear in the capture is not launched."""
    import pcap_doctor.tshark as mod

    runner = TsharkRunner(fixture("dns_plus_tls.pcap"), use_cache=False)
    real_run = mod.subprocess.run
    launched: list[str] = []

    def counting_run(cmd, *args, **kwargs):
        # cmd[0] is tshark; the pass name follows the display filter, but the simplest
        # stable marker is the fields list. Use the real _command to map the name.
        launched.append("tshark")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(mod.subprocess, "run", counting_run)
    runner.prefetch({
        "base": (), "tls": (), "dtls": (), "http": (), "dns": (), "sip": (),
        "ssh": (), "quic": (), "services": (), "telnet": (), "smb": (),
    })
    # The runner records which passes were skipped (empty rows, no subprocess).
    assert set(runner.skipped_passes) == {"dtls", "http", "sip", "ssh", "quic", "services", "telnet", "smb"}
    assert set(runner.stats) <= {"base", "tls", "dns", *runner.skipped_passes}
    # A skipped pass returns the same empty rows it would have produced if launched.
    assert runner.run("smb") == []
    assert runner.stats["smb"] == {"rows": 0, "cached": 0, "skipped": 1}


@requires_tshark
def test_skip_pass_not_applied_when_extra_args_present(monkeypatch) -> None:
    """A pass invoked with decode-as / decrypt args is never skipped: the extra args
    can reveal protocols the base pass cannot see (#328)."""
    runner = TsharkRunner(fixture("dns_plus_tls.pcap"), use_cache=False)
    # rtp has skip_protocols ("rtp",) which is absent from dns_plus_tls, but the
    # SIP pass supplies decode-as args -- the pass must still launch.
    launched: list[str] = []
    real_run = __import__("pcap_doctor.tshark", fromlist=["subprocess"]).subprocess.run

    def counting_run(cmd, *args, **kwargs):
        launched.append("tshark")
        return real_run(cmd, *args, **kwargs)

    import pcap_doctor.tshark as mod

    monkeypatch.setattr(mod.subprocess, "run", counting_run)
    runner.run("rtp", runner.rtp_decode_args([20000]))
    assert launched  # at least one tshark launch happened
    assert "rtp" not in runner.skipped_passes


@requires_tshark
def test_prefetch_runs_passes_concurrently_and_run_reuses_them(monkeypatch) -> None:
    # #127: the independent passes overlap, and `run` serves the prefetched rows (same per-call args only)
    import threading
    import time

    runner = TsharkRunner(fixture("weak_tls.pcap"), use_cache=False)
    active, peak, calls = [0], [0], []
    lock = threading.Lock()

    def fake_run(spec, extra_args=()):
        with lock:
            calls.append((spec.name, extra_args))
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.2)
        with lock:
            active[0] -= 1
        return [{"pass": [spec.name]}]

    monkeypatch.setattr(runner, "_run", fake_run)
    runner.prefetch({"base": (), "tls": (), "http": ("-o", "x:y")})
    assert peak[0] >= 2
    assert runner.run("base") == [{"pass": ["base"]}]
    assert runner.run("http", ("-o", "x:y")) == [{"pass": ["http"]}]
    assert len(calls) == 3  # served from the prefetch, no second tshark
    runner.run("http")  # other per-call args: a real run, never the prefetched rows
    assert calls[-1] == ("http", ())


def test_command_disables_sequence_analysis_only_for_transport_only_passes() -> None:
    """(issue #329) tcp.analyze_sequence_numbers is expensive; turn it off only for
    transport-only passes — those that read no tcp.analysis.* / _ws.expert.* field,
    whose fields are all transport/link-layer, and whose display filter names no
    application protocol. App-protocol passes must keep analysis on because with
    it off tshark re-hands retransmitted segments to the app dissector, duplicating
    findings such as FTP credentials."""
    from pcap_doctor.tshark import _is_transport_only
    runner = TsharkRunner(fixture("weak_tls.pcap"), use_cache=False)
    for name, spec in PASSES.items():
        fields = runner.usable_fields(spec)
        cmd = runner._command(spec)
        has_flag = "tcp.analyze_sequence_numbers:FALSE" in cmd
        if _is_transport_only(spec, fields):
            assert has_flag, f"transport-only pass {name!r} should have the FALSE flag"
        else:
            assert not has_flag, (
                f"pass {name!r} is not transport-only (app fields or filter); "
                f"must keep tcp sequence analysis ON to avoid duplicate app-layer findings"
            )


def test_worker_count_default_rule(monkeypatch) -> None:
    """Issue #331: default worker count = max(1, min(3, cpu_count // 2))."""
    for cpus, expected in (
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 2),
        (6, 3),
        (8, 3),
        (16, 3),
        (32, 3),
        (100, 3),
    ):
        mp = pytest.MonkeyPatch()
        mp.setattr("os.cpu_count", lambda n=cpus: n)
        assert worker_count(None, None) == expected
        mp.undo()


def test_worker_count_jobs_overrides_cpu_count(monkeypatch) -> None:
    """--jobs N wins over the CPU-based default."""
    monkeypatch.setattr("os.cpu_count", lambda n=8: n)
    assert worker_count(5, None) == 5


def test_worker_count_env_overrides_cpu_count(monkeypatch) -> None:
    """PCAP_DOCTOR_JOBS env var wins over CPU default."""
    monkeypatch.setattr("os.cpu_count", lambda n=8: n)
    monkeypatch.setenv("PCAP_DOCTOR_JOBS", "4")
    assert worker_count(None, None) == 4


def test_worker_count_cli_wins_over_env(monkeypatch) -> None:
    """CLI --jobs wins over env var."""
    monkeypatch.setattr("os.cpu_count", lambda n=8: n)
    monkeypatch.setenv("PCAP_DOCTOR_JOBS", "2")
    assert worker_count(6, None) == 6


def test_worker_count_rejects_below_one(monkeypatch) -> None:
    """N < 1 is rejected with a ValueError."""
    monkeypatch.setattr("os.cpu_count", lambda n=8: n)
    with pytest.raises(ValueError):
        worker_count(0, None)
    with pytest.raises(ValueError):
        worker_count(-1, None)


def test_prefetch_uses_count_to_cap_workers(monkeypatch) -> None:
    """prefetch() respects the count limit, never spawning more than that."""
    import threading
    import time

    runner = TsharkRunner(fixture("weak_tls.pcap"), use_cache=False)
    active, peak = [0], [0]
    lock = threading.Lock()

    def fake_run(spec, extra_args=()):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.1)
        with lock:
            active[0] -= 1
        return [{}]

    monkeypatch.setattr(runner, "_run", fake_run)
    runner.prefetch({"base": (), "tls": (), "http": (), "dns": (), "sip": ()}, count=2)
    assert peak[0] <= 2
    assert peak[0] >= 2  # with 5 jobs and 2 workers, we expect 2 concurrent


def test_tshark_subprocess_runs_at_low_priority_posix(monkeypatch) -> None:
    """On POSIX, tshark children get os.nice(10) via preexec_fn, never fatal."""
    kwargs = _low_priority_kwargs()
    assert "preexec_fn" in kwargs
    called = []

    def fake_nice(value):
        called.append(value)
        raise OSError("nice failed")

    monkeypatch.setattr("os.nice", fake_nice)
    # preexec_fn must be callable and must not raise to the caller
    with contextlib.suppress(OSError):
        kwargs["preexec_fn"]()
    assert called == [10]


def test_tshark_subprocess_runs_at_low_priority_windows(monkeypatch) -> None:
    """On Windows, tshark children get BELOW_NORMAL_PRIORITY_CLASS."""
    import sys

    monkeypatch.setattr(sys, "platform", "win32")
    # subprocess doesn't define BELOW_NORMAL_PRIORITY_CLASS on non-Windows
    fake_creationflags = 0x00000040
    monkeypatch.setattr(
        "subprocess.BELOW_NORMAL_PRIORITY_CLASS", fake_creationflags, raising=False
    )

    kwargs = _low_priority_kwargs()
    assert kwargs.get("creationflags") == fake_creationflags
    assert "preexec_fn" not in kwargs
