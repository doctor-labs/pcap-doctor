# SERVICE_PIA_EXPOSED

## What it means
Traffic involving the PIA protocol (commonly TCP/6543) was observed.

## Why it matters
Legacy or unauthenticated protocol endpoints can expose management or device functions to unauthorized parties.

## How to fix
- Restrict or retire PIA endpoints and require authenticated, encrypted management protocols.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_PIA_EXPOSED must be absent once the endpoint is removed or protected.
