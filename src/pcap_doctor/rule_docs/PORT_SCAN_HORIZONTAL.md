# PORT_SCAN_HORIZONTAL

## What it means
One source IP established completed TCP connections (or otherwise reached) a single destination port on at least 15 distinct destination hosts.

## Why it matters
Hitting the same port across many hosts is network-wide reconnaissance: a worm, bot or scanner is checking which hosts expose a service (for example port 445) before targeting the responsive ones. It maps the attack surface across the whole subnet.

## How to fix
- Block or rate-limit the source IP at the perimeter.
- If this was authorised testing, record the authorised window and scope.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; PORT_SCAN_HORIZONTAL must not be reported from that source.
