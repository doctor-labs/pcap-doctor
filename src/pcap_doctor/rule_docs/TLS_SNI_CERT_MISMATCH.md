# TLS_SNI_CERT_MISMATCH

## What it means
The client sent an SNI (server name indication) value, but the leaf certificate's subject names (SAN dNSName or commonName) do not cover that SNI.

## Why it matters
The certificate does not match the identity the client intended. This is either a misconfiguration or an attack surface: an on-path attacker may be redirecting the client to a server with a certificate for a different name, and the mismatch is what gives the attack away.

## How to fix
- Present a certificate whose SAN/CN matches the SNI the client requested.
- If the service legitimately serves many names, use a wildcard or multi-domain certificate.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_SNI_CERT_MISMATCH must not be reported.
