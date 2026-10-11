# PORT_SCAN_VERTICAL

## What it means
One source IP established completed TCP connections (or otherwise reached) at least 15 distinct destination ports on a single destination host.

## Why it matters
Opening a large port range on a single host is host reconnaissance: an attacker (or automated scanner) is probing which services are listening. Each reachable port confirms an exploitable or mis-configured service is present.

## How to fix
- Block or rate-limit the source IP at the perimeter.
- If this was authorised testing, record the authorised window and scope.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; PORT_SCAN_VERTICAL must not be reported from that source.
