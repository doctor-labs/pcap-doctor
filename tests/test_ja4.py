"""JA4 / JA4S TLS fingerprints (issue #258). Expected values come from FoxIO's reference ja4.py."""

from __future__ import annotations

from conftest import CAPTURES, requires_tshark
from pcap_doctor.index import ja4s_fingerprint

# capture -> client port -> (JA4, JA4S)
EXPECTED = {
    "tls12-aes256gcm.pcap": {"50600": ("t12d010300_b8179719e6e3_fee41c0d62a8", "t120100_00a9_bc98f8e001b5")},
    "tls13-rfc8446.pcap": {
        "38288": ("t00i180900_e8a523a41297_78e6aca7449b", "t130200_1301_234ea6891581"),
        "38290": ("t00i181200_e8a523a41297_9fc0c022da54", "t130300_1301_6bbbaf601ed8"),
    },
}


@requires_tshark
def test_ja4_and_ja4s_match_the_reference(analyze_capture) -> None:
    for name, ports in EXPECTED.items():
        sessions = list(analyze_capture(CAPTURES / name).index.tls.values())
        for port, (ja4, ja4s) in ports.items():
            (s,) = [s for s in sessions if f":{port}<->" in s.key or s.key.endswith(f":{port}")]
            assert (s.ja4, s.ja4s) == (ja4, ja4s), (name, port)


def test_ja4s_keeps_extension_order_and_reads_alpn_and_dtls() -> None:
    row = {
        "tls.handshake.ciphersuite": ["0x1301"],
        "tls.handshake.version": ["0x0303"],
        "tls.handshake.extensions.supported_version": ["0x0304"],
        "tls.handshake.extension.type": ["43", "51", "16"],
        "tls.handshake.extensions_alpn_str": ["h2"],
    }
    assert ja4s_fingerprint(row, "tls") == "t1303h2_1301_19fd10492780"
    dtls = {"tls.handshake.ciphersuite": ["0xc0ae"], "tls.handshake.version": ["0xfefd"]}
    assert ja4s_fingerprint(dtls, "dtls") == "dd20000_c0ae_000000000000"
    assert ja4s_fingerprint({}, "tls") is None
