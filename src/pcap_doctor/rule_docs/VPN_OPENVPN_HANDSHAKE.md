# VPN_OPENVPN_HANDSHAKE

## What it means
The capture contains traffic that tshark's OpenVPN dissector has recognised on
UDP or TCP port 1194. The first byte of the OpenVPN payload contains an opcode
in its top 5 bits; the handshake opcodes (P_CONTROL_HARD_RESET_CLIENT_V1 and
P_CONTROL_V1) are the ones that establish the OpenVPN control channel.

## Why it matters
OpenVPN establishes an encrypted tunnel using its own control protocol. An
unexpected OpenVPN handshake means a host is negotiating a tunnel with a peer it
should not be talking to, which can bypass perimeter controls or exfiltrate
traffic.

## How to fix
- Confirm the OpenVPN peer is an authorised VPN endpoint for this network.
- If it is unexpected, block UDP/TCP 1194 at the firewall and investigate the
  host that originated the traffic.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`;
VPN_OPENVPN_HANDSHAKE will still be reported while the OpenVPN flow is present.
Once the handshake is blocked or removed, the finding disappears.
