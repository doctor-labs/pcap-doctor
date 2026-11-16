# SERVICE_DHT_BOOTSTRAP

## What it means
BitTorrent DHT traffic was observed, indicating peer discovery/bootstrap activity that advertises the client's presence and address to the DHT network.

## Why it matters
DHT participation leaks addressing and activity metadata to other peers and observers, and it can indicate unauthorized peer-to-peer usage.

## How to fix
- Disable DHT or confine BitTorrent traffic to approved networks when peer discovery is not wanted.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_DHT_BOOTSTRAP must be absent when DHT is disabled.
