"""Suricata-style classtype categories on every finding code (issue #241).

The rule registry maps each code to a Suricata classtype (``classification.config`` vocabulary), shown
next to the existing fields in the JSON and EVE outputs. Unmapped codes fall back to ``misc-activity``.
"""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.eve import build_eve
from pcap_doctor.index import build_index
from pcap_doctor.models import CaptureInfo, Finding, Report, Stats
from pcap_doctor.output import json_envelope
from pcap_doctor.rules import CLASS_TYPES, RULES, classtype_of

#: Every code the rule registry must map (the full set of detector codes in src/pcap_doctor/rules.py).
CODES = (
    "TLS_VERSION_DEPRECATED", "TLS_LEGACY_RECORD_VERSION", "TLS_CIPHER_UNKNOWN", "TLS_CIPHER_WEAK",
    "TLS_OFFERS_WEAK_CIPHERS", "TLS_NO_FORWARD_SECRECY", "TLS_KEY_IN_FIRMWARE", "TLS_CERT_EXPIRED",
    "TLS_CERT_EXPIRED_NOW", "TLS_CERT_EXPIRING", "TLS_CERT_WEAK_KEY", "TLS_CERT_WEAK_SIGALG",
    "TLS_CERT_NOT_YET_VALID", "TLS_SNI_CERT_MISMATCH", "TLS_NO_EXTENDED_MASTER_SECRET",
    "TLS_WEAK_DH_GROUP", "TLS_NO_OCSP_STAPLE", "TLS_SELF_SIGNED_CHAIN", "TLS_FATAL_ALERT",
    "TLS_WARNING_ALERT", "TLS_HANDSHAKE_TRUNCATED", "TLS_JA3_FLEET", "TLS_HEARTBLEED_PROBE",
    "TLS_COMPRESSION_ENABLED", "TLS_INSECURE_RENEGOTIATION", "CLEARTEXT_CREDENTIAL", "HTTP_BASIC_AUTH",
    "HTTP_CLEARTEXT_AUTH", "HTTP_CLEARTEXT", "HTTP_COOKIE_NO_SECURE", "CLEARTEXT_SERVICE",
    "SERVICE_ON_ODD_PORT", "SYN_SCAN_SHAPE", "PORT_SCAN_VERTICAL", "PORT_SCAN_HORIZONTAL",
    "BEACONING_SHAPE", "SIP_CLEARTEXT_SIGNALLING", "SDP_NO_CRYPTO_ATTR", "RTP_MEDIA_UNPROTECTED",
    "RTP_VOLUME_ANOMALY", "DNS_CLEARTEXT", "DNS_TUNNEL_SHAPE", "DNS_EXTERNAL_RESOLVER",
    "QUIC_PAYLOAD_OPAQUE", "SSH_WEAK_KEX", "SSH_WEAK_CIPHER", "SSH_WEAK_MAC", "SSH_WEAK_HOSTKEY",
    "SSH_TERRAPIN_EXPOSED", "SMB1_IN_USE", "SMB_SIGNING_NOT_REQUIRED", "SMB_NULL_SESSION",
    "SMB_ADMIN_SHARE_ACCESS", "SMB_REMOTE_EXEC_PIPE", "SMB_EXECUTABLE_ON_SHARE", "SIGNATURE_MATCH",
    "BRUTE_FORCE_SUSPECTED", "ARP_SPOOFING_SUSPECTED", "ICMP_REDIRECT", "CAPTURE_LOSS",
    "TLS_SERVER_CIPHER_PREFERENCE", "INTERESTING_HOSTNAME", "HTTP_MISSING_SECURITY_HEADERS",
    "HTTP_WEB_ATTACK_SQLI", "HTTP_WEB_ATTACK_XSS", "HTTP_WEB_ATTACK_LFI", "HTTP_WEB_ATTACK_TRAVERSAL", "HTTP_WEB_ATTACK_COMMAND_INJECTION",
)


def test_every_registry_code_resolves_to_an_allowed_classtype() -> None:
    assert set(CODES) == set(RULES)
    for code in CODES:
        assert classtype_of(code) in CLASS_TYPES, code


def test_the_mapping_and_the_misc_activity_default() -> None:
    assert classtype_of("TLS_NO_FORWARD_SECRECY") == "policy-violation"
    assert classtype_of("SYN_SCAN_SHAPE") == "attempted-recon"
    assert classtype_of("PORT_SCAN_HORIZONTAL") == "attempted-recon"
    assert classtype_of("BEACONING_SHAPE") == "trojan-activity"
    assert classtype_of("SSH_WEAK_KEX") == "attempted-admin"
    assert classtype_of("SMB1_IN_USE") == "protocol-command-decode"
    assert classtype_of("SIGNATURE_MATCH") == "attempted-admin"
    assert classtype_of("CAPTURE_LOSS") == "misc-activity"
    assert classtype_of("NOT_A_CODE") == "misc-activity"  # unmapped codes take the default


def test_the_json_envelope_gains_the_classtype_field() -> None:
    finding = Finding.make(
        detector="d4.dns_quic_ssh", code="DNS_CLEARTEXT", title="t", severity="medium", confidence="high",
        category="dns", summary="", scope="s",
    )
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    env = json_envelope(Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=[finding]))
    f = env["findings"][0]
    assert f["classtype"] == "policy-violation"
    assert f["category"] == "DNS" and f["id"] == "DNS_CLEARTEXT"  # the existing fields are untouched


@requires_tshark
def test_an_existing_fixture_report_gains_only_the_field(tmp_path, cache_dir, analyze_capture) -> None:
    pcap = fixture("weak_tls.pcap")
    report = analyze_capture(pcap).report
    env = json_envelope(report)
    for f in env["findings"]:
        assert f["classtype"] in CLASS_TYPES
    assert {f["id"] for f in env["findings"]} == {
        "TLS_CIPHER_WEAK", "TLS_NO_FORWARD_SECRECY", "TLS_SELF_SIGNED_CHAIN", "TLS_VERSION_DEPRECATED"
    }


@requires_tshark
def test_the_eve_alert_carries_the_classtype(cache_dir) -> None:
    index = build_index(fixture("weak_tls.pcap"))
    alerts = [e for e in build_eve(index, ("alert",))]
    assert alerts, "weak_tls.pcap produces no alert events"
    for ev in alerts:
        assert ev["alert"]["classtype"] in CLASS_TYPES
        assert {"signature_id", "category", "severity"} <= set(ev["alert"])  # the existing fields are untouched
