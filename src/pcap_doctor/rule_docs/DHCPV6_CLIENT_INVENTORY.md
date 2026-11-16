# DHCPV6_CLIENT_INVENTORY

## What it means
A host took part in a DHCPv6 exchange: the finding names its DUID (the hardware address it used), the address it was given and the lifetime of that address.

## Why it matters
DHCPv6 says the same thing DHCP does, in the same way: the client's DUID and the address it was handed are on the wire in the clear, to anything that can hear the exchange. It is the same inventory and the same disclosure, on an IPv6 segment.

## How to fix
Inventory only. Note the host and the address it was given, and check it against the asset register. DHCPv6 is unauthenticated by design, so a segment that runs it should be treated as trusted: filter the relay traffic at the edge rather than expecting the client to tell a rogue server apart.

## How to verify
Capture the same segment again and run `pcap-doctor analyze <capture>`; the host must still be listed with the same DUID and address.
