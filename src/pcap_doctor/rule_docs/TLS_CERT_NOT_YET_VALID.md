# TLS_CERT_NOT_YET_VALID

## What it means
The certificate's validity window starts after the capture began, so the certificate was not yet valid when the TLS handshake happened.

## Why it matters
A certificate whose notBefore is in the future is not trusted by normal path-building. If the traffic was accepted anyway, validation was disabled or bypassed, which means an attacker who can mint or roll back certificates can impersonate the service.

## How to fix
- Replace the certificate with one whose validity window covers the capture.
- Check for clock skew on the server that presents the certificate; fix the system clock and automate renewal with alerting.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_NOT_YET_VALID must not be reported.
