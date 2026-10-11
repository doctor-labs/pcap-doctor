# ARP_SPOOFING_SUSPECTED

## What it means
An IPv4 address was claimed by one MAC in an ARP reply and later claimed by a different MAC in another ARP reply within the same capture.

## Why it matters
Two different MAC addresses answering for the same IP is the signature of ARP spoofing (or an uncoordinated duplicate address): a host is presenting itself as another IP on the LAN. An attacker in this position can intercept, modify or drop traffic for that IP, which is a classic man-in-the-middle position; a duplicate address instead will cause intermittent connectivity failures for the real owner.

## How to fix
- Find which host actually owns the IP (check the DHCP lease table and the switch/MAC table).
- Enable Dynamic ARP Inspection (DAI) on the switch, or install static ARP entries for gateways and critical hosts.
- Quarantine the host whose MAC appeared second to stop further spoofing attempts.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; ARP_SPOOFING_SUSPECTED must no longer be reported once the conflicting ARP replies stop.
