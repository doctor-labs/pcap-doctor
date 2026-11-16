# CLEARTEXT_IRC

## What it means
IRC service traffic was observed without transport encryption, exposing service inventory and protocol exchanges in cleartext.

## Why it matters
Cleartext IRC reveals channels, nicks and messages to on-path observers and can expose session details (credential extraction, if any, is reported separately).

## How to fix
- Use IRC over TLS (commonly port 6697) and restrict cleartext IRC access.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_IRC must be absent once IRC uses TLS.
