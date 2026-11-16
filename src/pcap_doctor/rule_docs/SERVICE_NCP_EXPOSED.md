# SERVICE_NCP_EXPOSED

## What it means
Traffic involving the NCP protocol (commonly TCP/524) was observed.

## Why it matters
NCP can expose file and print services; legacy or weakly protected deployments increase the risk of unauthorized access.

## How to fix
- Restrict NCP access, disable it where unused, and use authenticated, modern configurations.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_NCP_EXPOSED must be absent once access is restricted or the service is removed.
