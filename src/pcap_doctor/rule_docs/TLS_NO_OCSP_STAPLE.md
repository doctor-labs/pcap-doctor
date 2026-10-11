# TLS_NO_OCSP_STAPLE

## What it means
The negotiated version is TLS 1.0, 1.1, or 1.2, the client sent the status_request extension (type 5) in its ClientHello, and the server neither echoed extension 5 in its ServerHello nor sent a CertificateStatus message.

## Why it matters
Without a stapled OCSP response, clients must query the certificate authority's revocation server themselves or skip revocation checking entirely. The extra round trip degrades the handshake, and a client that skips revocation checking is vulnerable to accepting a revoked certificate.

## How to fix
- Enable OCSP stapling on the TLS server so it returns the CA's signed OCSP response during the handshake.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_NO_OCSP_STAPLE must not be reported once the server staples an OCSP response or the extension is present in the ServerHello.
