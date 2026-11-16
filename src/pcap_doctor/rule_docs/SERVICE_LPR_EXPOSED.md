# SERVICE_LPR_EXPOSED

## What it means
Traffic involving the LPR printing service (TCP/515) was observed.

## Why it matters
LPR can accept print jobs with weak or no strong authentication, exposing printers and potentially sensitive documents to unauthorized use.

## How to fix
- Restrict LPR to trusted hosts or migrate to IPP over TLS with authentication.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_LPR_EXPOSED must be absent once the service is restricted or replaced.
