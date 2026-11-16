# RTSP_CONTROL_EXCHANGE

## What it means
The capture shows RTSP control traffic including DESCRIBE and/or PLAY methods. Session setup and control messages are observable on the wire.

## Why it matters
Cleartext RTSP control traffic can expose stream URLs, session details, and control actions to anyone on the network path. Attackers may learn stream structure, hijack sessions, or discover endpoints to target.

## How to fix
Use RTSPS (RTSP over TLS) where supported, require strong authentication for control endpoints, and avoid embedding credentials in URLs. Restrict camera and media server access to trusted networks and authorised clients.

## How to verify
After remediation, recapture traffic and confirm RTSP control messages are protected by TLS or no longer traverse untrusted networks. Verify unauthenticated clients cannot issue DESCRIBE/PLAY requests.
