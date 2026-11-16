# WEBRTC_DTLS_ASSOCIATION

## What it means
The capture contains DTLS session traffic observed alongside STUN/ICE packets, which is consistent with a WebRTC context where DTLS is used to establish keys for secure media (DTLS-SRTP).

## Why it matters
Seeing DTLS with STUN/ICE suggests real-time communication signalling is present. While DTLS is intended to protect key exchange, misconfiguration can still leave media unprotected or allow downgrade to weaker security if SRTP is not enforced correctly.

## How to fix
Ensure WebRTC stacks negotiate DTLS-SRTP for all media, disable legacy or insecure keying mechanisms, and require authenticated ICE/TURN where applicable. Apply current platform and library security updates.

## How to verify
Capture a new session and confirm DTLS handshakes complete successfully and media is carried as SRTP rather than plaintext RTP. Validate policy enforcement in client and server configuration.
