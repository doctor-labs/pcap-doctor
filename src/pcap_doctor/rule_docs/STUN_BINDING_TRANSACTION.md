# STUN_BINDING_TRANSACTION

## What it means
The capture contains a STUN/TURN binding request and a corresponding success response between the same pair of endpoints. This shows that connectivity checks or relay allocation signalling completed at the protocol level.

## Why it matters
STUN and TURN traffic is normal for ICE/WebRTC, but it can also reveal network topology details and indicates that real-time media or NAT traversal is in use. Unexpected STUN/TURN endpoints may point to misconfiguration, exposed relay services, or unwanted peer-to-peer connectivity.

## How to fix
Restrict STUN/TURN usage to approved servers and clients. Require authentication and message integrity for TURN allocations, prefer TURN over TLS where possible, and monitor for unexpected relay or peer endpoints.

## How to verify
Recapture traffic after changes and confirm only expected STUN/TURN endpoints appear. Review server logs for authenticated allocations and validate that unauthorised clients cannot obtain bindings or relay access.
