"""Host, file and credential tabs over the index (issue #252)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor import browse_tabs
from pcap_doctor.index import IndexBuilder
from pcap_doctor.tshark import TsharkRunner


def _index(name: str):
    return IndexBuilder(TsharkRunner(fixture(name), use_cache=False)).build()


@requires_tshark
def test_hosts_tab_lists_every_host_with_os_guess(cache_dir) -> None:
    rows = browse_tabs.hosts(_index("http_basic.pcap"))
    assert {r.ip for r in rows} >= {"10.0.0.10", "10.0.0.20"}
    assert next(r for r in rows if r.ip == "10.0.0.10").os_guess == "Linux/Unix/Android/macOS"


@requires_tshark
def test_files_tab_has_smb_creates_with_frame_and_flow(cache_dir) -> None:
    rows = browse_tabs.files(_index("smb_attack.pcap"))
    psexec = next(r for r in rows if r.name == "PSEXESVC.exe")
    # 28 is the create request, 30 its response: which one tshark attributes the file name to varies by version (Linux 28, macOS 30)
    assert psexec.source == "smb" and psexec.frame in (28, 30) and psexec.flow


@requires_tshark
def test_credentials_tab_never_carries_the_secret(cache_dir) -> None:
    rows = browse_tabs.credentials(_index("telnet_login.pcap"))
    telnet = next(r for r in rows if r.source == "telnet")
    assert telnet.user == "admin"
    assert telnet.secret == "password of 16 chars"


@requires_tshark
def test_credentials_tab_redacts_http_basic_auth(cache_dir) -> None:
    rows = browse_tabs.credentials(_index("http_basic.pcap"))
    http = next(r for r in rows if r.source == "http")
    assert http.secret == "Basic <redacted 20 chars>"


@requires_tshark
def test_smb_identity_shows_as_credential_row(cache_dir) -> None:
    rows = browse_tabs.credentials(_index("files_mix.pcap"))
    assert any(r.source == "smb" and r.user == "bob" and r.secret == "" for r in rows)



@requires_tshark
def test_anonymous_smb_session_is_not_listed_as_a_credential(cache_dir) -> None:
    rows = browse_tabs.credentials(_index("smb_attack.pcap"))
    assert all(r.user != "NULL" for r in rows if r.source == "smb")
