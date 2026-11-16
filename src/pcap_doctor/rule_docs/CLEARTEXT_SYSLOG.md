# CLEARTEXT_SYSLOG

## What it means
Syslog messages were sent without transport encryption (typically UDP/514). The finding reports the sender, receiver, count and sampled facility, severity, hostname and message content visible in the capture.

## Why it matters
Cleartext syslog exposes operational detail, hostnames, application state and sometimes sensitive values to anyone on the network path, and it can be spoofed or altered.

## How to fix
- Send logs over TLS (RFC 5425), DTLS or another authenticated encrypted transport.
- Restrict UDP/514 with network controls and avoid placing credentials or tokens in log messages.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_SYSLOG must be absent once logs use an encrypted transport.
