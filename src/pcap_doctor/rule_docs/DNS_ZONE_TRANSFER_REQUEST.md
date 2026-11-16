# DNS_ZONE_TRANSFER_REQUEST

## What it means
A host sent a DNS zone transfer request (AXFR or IXFR) for a zone over unencrypted DNS. The finding names the requesting host, the destination server, the zone, the transfer type and the frame where it was observed.

## Why it matters
A successful zone transfer returns the records in a DNS zone — hostnames, IP addresses and other data — giving a detailed map of internal or authoritative infrastructure. When requested in cleartext, the request and any response are visible on the network path, and an unrestricted server may hand the zone to an unauthorized client.

## How to fix
- Allow zone transfers (AXFR/IXFR) only to explicitly authorized secondary servers, enforced by IP ACLs and authenticated with TSIG where supported.
- Refuse or ignore transfer requests from untrusted clients and monitor for unexpected AXFR/IXFR queries.
- Avoid exposing authoritative or internal DNS zones on networks where cleartext traffic can be observed.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`. DNS_ZONE_TRANSFER_REQUEST must be absent, or present only for transfers you have explicitly authorized between designated servers.
