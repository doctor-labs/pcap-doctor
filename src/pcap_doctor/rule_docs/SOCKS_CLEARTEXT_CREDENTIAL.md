# SOCKS_CLEARTEXT_CREDENTIAL

## What it means
A SOCKS proxy authentication credential was sent in cleartext, such as a SOCKS5 username/password subnegotiation (RFC 1929). The finding names the protocol, the account, and the frame where it was seen; the secret value itself is redacted.

## Why it matters
Anyone on the network path can capture the proxy credentials and use the proxy to reach internal resources or impersonate the user.

## How to fix
- Rotate the exposed SOCKS credentials immediately.
- Tunnel SOCKS over an encrypted channel (for example SSH or TLS) and avoid cleartext proxy authentication on untrusted networks.
- Prefer stronger authentication mechanisms where supported.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SOCKS_CLEARTEXT_CREDENTIAL must not be reported.
