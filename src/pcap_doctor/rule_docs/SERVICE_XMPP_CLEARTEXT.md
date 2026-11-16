# SERVICE_XMPP_CLEARTEXT

## What it means
XMPP client traffic (commonly TCP/5222) was observed without confirmed transport encryption, suggesting a stream that may not be STARTTLS-protected.

## Why it matters
Unprotected XMPP streams can expose identities, presence and messages to on-path observers.

## How to fix
- Require STARTTLS or use XMPP over TLS and enforce encrypted, authenticated streams.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_XMPP_CLEARTEXT must be absent once streams are encrypted.
