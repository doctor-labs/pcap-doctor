# KERBEROS_TICKET_ISSUED

## What it means
The capture contains a Kerberos AS-REP or TGS-REP that issued a ticket. The finding reports the principal, realm, service name, and whether the ticket is a `krbtgt` ticket-granting ticket (TGT) or a service ticket. No ticket, key, or ciphertext is included.

## Why it matters
Distinguishing TGTs from service tickets exposes authentication and delegation surface: service tickets show which services a principal can reach, and unexpected issuance can indicate delegated, forged, or excessive access. This is an exposure view, not proof of compromise.

## How to fix
- Review whether the principal should obtain tickets for the reported services.
- Limit unconstrained and constrained delegation; prefer resource-based constrained delegation where needed.
- Monitor TGS issuance for sensitive SPNs and alert on unusual principals or services.

## How to verify
Capture representative authentication traffic and confirm ticket issuance matches expected principals and services. Unexpected `KERBEROS_TICKET_ISSUED` findings should be investigated in KDC and directory logs.
