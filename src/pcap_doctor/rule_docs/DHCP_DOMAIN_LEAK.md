# DHCP_DOMAIN_LEAK

## What it means
A client sent the name of its domain in a DHCP request, in the clear. The finding quotes the domain the client broadcast.

## Why it matters
The domain name is a map of the network: it says which organisation this is, which naming scheme is in use, and often which machines exist. Every host on the segment learns it, including any host that has no business being there. It is a small leak that costs nothing to close.

## How to fix
Stop sending the domain name in DHCP (option 15 in IPv4, the domain search option in IPv6) if the clients do not need it — most clients only take it for the search suffix. On the edge, strip option 15 from the relay. If the domain must be advertised, put the segment on a VLAN where the name does not travel.

## How to verify
Capture the same segment again and run `pcap-doctor analyze <capture>`; DHCP_DOMAIN_LEAK must no longer be reported.
