# WEBRTC_MEDIA_UNPROTECTED

## What it means
RTP media packets in the capture are observable without SRTP protection in a context where WebRTC signalling (such as STUN/ICE or DTLS association) is present.

## Why it matters
Unprotected RTP exposes audio/video content and media metadata to eavesdropping and tampering on the network path. Attackers can listen to calls, capture sensitive information, or inject or modify media streams.

## How to fix
Enforce SRTP for all WebRTC/media streams using DTLS-SRTP keying. Disable plaintext RTP on media paths, require secure transport policies, and ensure middleboxes or gateways do not strip media protection.

## How to verify
Recapture traffic and confirm RTP payloads are no longer readable as plaintext media and that SRTP-protected packets are used instead. Perform end-to-end call tests to ensure media fails closed when SRTP cannot be negotiated.
