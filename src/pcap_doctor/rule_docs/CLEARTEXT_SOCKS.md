# CLEARTEXT_SOCKS

## What it means
SOCKS proxy traffic was observed without transport encryption, exposing proxy usage and destination requests in cleartext.

## Why it matters
Cleartext proxy traffic can reveal what hosts and services a client reaches through the proxy to anyone on the network path.

## How to fix
- Require authenticated SOCKS over an encrypted tunnel or restrict proxy access to trusted paths.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_SOCKS must be absent once proxy traffic is protected.
