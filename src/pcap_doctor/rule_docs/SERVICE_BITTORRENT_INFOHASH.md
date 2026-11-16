# SERVICE_BITTORRENT_INFOHASH

## What it means
BitTorrent peer-wire or related activity exposed an info-hash that identifies the content being announced or fetched.

## Why it matters
Info-hashes reveal peer-to-peer activity and can be correlated to specific content, which may violate policy or indicate unauthorized data transfer.

## How to fix
- Restrict or block BitTorrent where not authorized and monitor for unexpected peer-to-peer traffic.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_BITTORRENT_INFOHASH must be absent when BitTorrent traffic is removed or confined.
