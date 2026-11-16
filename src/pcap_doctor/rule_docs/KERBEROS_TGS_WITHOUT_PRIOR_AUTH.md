# KERBEROS_TGS_WITHOUT_PRIOR_AUTH

## What it means
A Kerberos TGS-REP issued a service ticket for a principal, but the capture contains no successful AS/TGS authentication for that principal earlier in the observed traffic. The finding reports the principal and service only; no ticket material is included.

## Why it matters
A service ticket without a prior observed authentication can indicate delegated access, a forged or replayed ticket context, or that the authenticating exchange occurred outside the capture window. It can expose delegation paths worth reviewing.

## How to fix
- Correlate the ticket grant with KDC, endpoint, and directory audit logs to confirm it is expected.
- Restrict delegation (disable unconstrained delegation; scope constrained delegation tightly).
- Enforce PAC validation and investigate unexpected service-ticket grants for sensitive services.

## How to verify
Collect a capture that includes the full authentication flow and re-run `pcap-doctor analyze <capture>`. The finding should disappear when the observed traffic includes the expected prior authentication for the same principal.
