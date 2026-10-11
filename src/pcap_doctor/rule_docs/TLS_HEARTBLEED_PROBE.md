# TLS_HEARTBLEED_PROBE

## What it means
The capture contains a TLS/DTLS heartbeat request (RFC 6520 type 1) whose claimed payload length, plus the 1-byte type and 2-byte length and 16-byte minimum padding, exceeds the record length. That is the on-wire signature of a Heartbleed (CVE-2014-0160) probe: a client asks for more payload bytes than the record can hold, so a vulnerable OpenSSL responder returns the bytes beyond the record, leaking its memory.

## Why it matters
A vulnerable OpenSSL 1.0.1 through 1.0.1f (and 0.9.8zh, 1.0.2-beta) answers the probe with up to 64 KiB of its own process memory per request, which can include other clients' session keys, the server's private key, and credentials. The probe is cheap and unauthenticated, so a single captured packet is enough to flag a host that answered it as worth rebuilding or rotating.

## How to fix
- Upgrade OpenSSL past 1.0.1g (or disable the heartbeat extension),
- Revoke and reissue the server certificate, and
- Rotate secrets that may have leaked.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_HEARTBLEED_PROBE must not be reported.
