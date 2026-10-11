# TLS_WEAK_DH_GROUP

## What it means
The TLS handshake negotiated a finite-field Diffie-Hellman (DHE) group whose prime is smaller than 2048 bits, derived from the ServerKeyExchange message's DH `p` length.

## Why it matters
A DH group smaller than 2048 bits is within precomputation range: an attacker who can run a one-time computation against the group can decrypt passive recordings of this session (the Logjam attack, CVE-2015-4000). Groups under 1024 bits are considered practically breakable.

## How to fix
- Use a 2048-bit or larger DH group from RFC 7919 (ffdhe2048 or larger).
- Prefer ECDHE key exchange, which is not affected by precomputation in the same way.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_WEAK_DH_GROUP must not be reported once a 2048-bit or larger group is selected.
