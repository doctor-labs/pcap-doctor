# SERVICE_IDENT_EXPOSED

## What it means
Traffic involving the Ident service (TCP/113) was observed, indicating exposure of connection ownership information.

## Why it matters
Ident can leak which local user owns a network connection, aiding reconnaissance and correlation.

## How to fix
- Disable or firewall Ident and avoid relying on it for authentication.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_IDENT_EXPOSED must be absent once the service is removed or blocked.
