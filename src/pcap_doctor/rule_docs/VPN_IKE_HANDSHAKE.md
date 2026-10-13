# VPN_IKE_HANDSHAKE

## What it means
The capture contains ISAKMP/IKE traffic on UDP port 500 or 4500. ISAKMP is the
Internet Security Association and Key Management Protocol: it is the handshake
that negotiates IPsec Security Associations. tshark has identified the ISAKMP
dissector on these packets, and the source or destination UDP port is 500
(ISAKMP) or 4500 (IPsec NAT-T).

## Why it matters
IKE/IPsec is how site-to-site and remote-access VPNs are built. An unexpected
IKE handshake means a host is negotiating an encrypted tunnel with a peer it
should not be talking to, which can bypass perimeter controls or exfiltrate
traffic. The exchange type tells you which phase of the negotiation is in
progress (IKE_SA_INIT, IKE_AUTH, Quick Mode, etc.).

## How to fix
- Confirm the IKE peer is an authorised VPN gateway for this network.
- If it is unexpected, block UDP 500 and 4500 at the firewall and investigate
  the host that originated the traffic.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`;
VPN_IKE_HANDSHAKE will still be reported while the IKE handshake is present.
Once the handshake is blocked or removed, the finding disappears.
