# TLS_COMPRESSION_ENABLED

## What it means
The TLS ServerHello selects a non-null compression method (any value other than 0, which is the only defined method meaning "null/identity").

## Why it matters
TLS-level compression (defined in RFC 5246 section 6.2.1) exposes ciphertext length to an on-path observer. An attacker who can inject chosen plaintext into the compressed stream can recover secret bytes — the CRIME attack (CVE-2012-4929). Modern implementations default to the null method; any other value means compression is active.

## How to fix
- Disable TLS compression on the server. Most servers (OpenSSL, NSS, GnuTLS) compile it out or set the compression method to NULL by default; confirm the runtime is not offering a non-null method.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_COMPRESSION_ENABLED must not be reported once the ServerHello selects the null (0) compression method. You can also inspect the ServerHello directly: `tshark -r <capture> -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.comp_method`.
