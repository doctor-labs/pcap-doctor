"""HASSH / HASSHServer fingerprints on the ssh_weak fixture (issue #259)."""

from __future__ import annotations

import hashlib

from conftest import fixture, requires_tshark

# client source port -> (hassh, hasshServer); hassh values checked against md5 of the HASSH string
EXPECTED = {
    "43100": ("461be81f4e1902af512743bc0cd03226", "461be81f4e1902af512743bc0cd03226"),
    "43200": ("260d48a27d34a2fe350597c3b19aded0", "260d48a27d34a2fe350597c3b19aded0"),
    "43300": ("30323639bf015c06b14fa2c498874588", "7d4da1e4b2dbfbb400f204df0252ce47"),
    "43400": ("0e987a244cbe0f900e1d2f620f427111", "a8bb0fb2a64c00867b899efe3cc6d355"),
}


@requires_tshark
def test_hassh_and_hassh_server_per_session(analyze_capture) -> None:
    index = analyze_capture(fixture("ssh_weak.pcap")).index
    got = {s.key.split("<->")[0].rsplit(":", 1)[1]: s for s in index.ssh}
    assert set(got) == set(EXPECTED), sorted(got)
    for port, (hassh, server) in EXPECTED.items():
        s = got[port]
        assert (s.hassh, s.hassh_server) == (hassh, server), port
        assert hashlib.md5(s.hassh_algorithms.encode()).hexdigest() == s.hassh
        assert hashlib.md5(s.hassh_server_algorithms.encode()).hexdigest() == s.hassh_server
    assert got["43100"].hassh_algorithms.startswith("diffie-hellman-group1-sha1;aes128-cbc,")
