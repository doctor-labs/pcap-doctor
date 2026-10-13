# VPN_WIREGUARD_HANDSHAKE

## What it means
The capture contains UDP traffic on port 51820 whose payload starts with a valid
WireGuard message-type field (a little-endian 32-bit integer with value 1–4).
WireGuard is a modern VPN tunnel protocol; its handshake (type 1 = Initiation,
type 2 = Response, type 3 = Cookie Reply) derives the session keys, and type 4
is encrypted transport data on an established tunnel.

## Why it matters
WireGuard traffic is opaque to inspection: once the handshake completes, all
payload is encrypted. An unexpected WireGuard handshake means a host is
establishing an encrypted tunnel with a peer that may bypass network controls
or exfiltrate data. Because WireGuard is connectionless (stateless UDP), it
does not appear in TLS or SSH indexes — only a protocol-aware scan finds it.

## How to fix
- Confirm the WireGuard peer is expected for this host.
- If unexpected, block UDP 51820 at the perimeter and investigate the
  originating host for a rogue tunnel client or malware.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`;
VPN_WIREGUARD_HANDSHAKE will still be reported while the WireGuard flow is
present. Once the flow is blocked or removed, the finding disappears.
