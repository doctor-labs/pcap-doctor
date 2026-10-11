# TLS_NO_EXTENDED_MASTER_SECRET

## What it means
The negotiated version is TLS 1.0, 1.1 or 1.2, and the server hello does not contain the extended master secret extension (type 23, RFC 7627).

## Why it matters
Without extended master secret, the session master secret is derived from the handshake messages that a MITM can manipulate. This exposes the session to the triple-handshake attack and related key-reuse weaknesses; the master secret is not bound to the full handshake transcript.

## How to fix
- Enable the `extended_master_secret` option on the TLS 1.2 server.
- Prefer migrating to TLS 1.3, where extended master secret is mandatory.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_NO_EXTENDED_MASTER_SECRET must not be reported once the extension is present or the server moves to TLS 1.3.
