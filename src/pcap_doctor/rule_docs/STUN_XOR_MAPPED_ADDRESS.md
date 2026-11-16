# STUN_XOR_MAPPED_ADDRESS

## What it means
A STUN response in the capture includes an XOR-MAPPED-ADDRESS attribute, exposing a reflexive transport address (IP address and port) as seen by the STUN server.

## Why it matters
Reflexive addresses are part of ICE connectivity establishment, but they disclose externally visible addressing information. In sensitive environments this can aid reconnaissance or reveal unexpected NAT mappings and network paths.

## How to fix
Limit STUN/TURN exposure to necessary services and trusted networks. Use authenticated TURN where relaying is required, and review firewall/NAT policies so only intended reflexive candidates are reachable.

## How to verify
Capture traffic again and confirm XOR-MAPPED-ADDRESS values correspond only to approved public interfaces and ports. Ensure unexpected candidates no longer appear in ICE/STUN signalling.
