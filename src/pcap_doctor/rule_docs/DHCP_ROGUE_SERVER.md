# DHCP_ROGUE_SERVER

## What it means
Two or more DHCP servers answered the same transaction, and they did not agree: each offered a different address. The finding names the transaction and the servers that answered it.

## Why it matters
The client takes whichever offer it hears first, so a host anywhere on the segment can answer a DISCOVER before the real server does and hand out an address of its choosing. That is the standard way to put a machine in the path of a victim: give it the gateway, the DNS server or the file server the victim will use next. Two servers disagreeing is the fingerprint of that, and it is visible in the capture without touching anything.

## How to fix
- Find the other server: the finding names the address each one answered from, so the host holding the rogue service is known.
- Disable it, or block DHCP server traffic (UDP port 67) to the network so only the authorised server can answer.
- On the edge, enable DHCP snooping or relay, so the client cannot be served by a host on the segment.

## How to verify
Capture the same segment again and run `pcap-doctor analyze <capture>`; DHCP_ROGUE_SERVER must no longer be reported, and only one server may answer a given transaction.
