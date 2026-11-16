# DHCP_VENDOR_FINGERPRINT

## What it means
A client sent a vendor class identifier in a DHCP request, in the clear. The finding quotes what the client announced.

## Why it matters
The vendor class usually names the device model or the operating system. That is the last step of reconnaissance: an attacker who knows the model knows which of its firmware vulnerabilities apply, and the model is broadcast to anyone listening before the host has even joined the network.

## How to fix
Inventory only, but two actions follow:
- Check the announced model against the known issues for that firmware; a device announcing itself is a device with a known attack surface.
- On the edge, strip option 60 (and the IPv6 vendor class) from relayed requests if the segment does not need it.

## How to verify
Capture the same segment again and run `pcap-doctor analyze <capture>`; DHCP_VENDOR_FINGERPRINT must no longer be reported.
