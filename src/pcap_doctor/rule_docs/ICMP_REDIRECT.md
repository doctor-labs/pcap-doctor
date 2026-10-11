# ICMP_REDIRECT

## What it means
A host sent an ICMP redirect message (type 5) telling other hosts to route a destination through a different next-hop gateway.

## Why it matters
ICMP redirects let a router reassign a peer's default gateway, and a forged redirect lets an attacker silently rewire a victim's routing so that traffic flows through a box they control. Even legitimate redirects are a network-wide configuration smell that is frequently abused as a man-in-the-middle foothold.

## How to fix
- Ignore ICMP redirects on hosts (set `accept_redirects=0` on Linux/BSD, disable ICMP redirects via Group Policy on Windows, or `ipv4.conf.all.send_redirects=0` and `net.ipv4.conf.all.accept_redirects=0`).
- Find the sender of the redirect and confirm it is an authorised router; remove or re-secure any unexpected sender.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; ICMP_REDIRECT must no longer be reported once the redirect messages stop.
