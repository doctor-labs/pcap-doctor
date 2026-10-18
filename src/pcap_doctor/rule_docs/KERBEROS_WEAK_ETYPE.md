# KERBEROS_WEAK_ETYPE

## What it means
A Kerberos AS or TGS reply carries a deprecated encryption type: DES (etype 1 or 3) or RC4-HMAC (etype 23 or 24). The finding names the principal and the etype; it never contains a ticket or key.

## Why it matters
DES and RC4-HMAC keys are weak (RFC 6649). Tickets encrypted with them can be cracked offline far more cheaply than AES tickets, which exposes the service or account key.

## How to fix
- Disable DES and RC4-HMAC for Kerberos (Windows: "Network security: Configure encryption types allowed for Kerberos", AES-only).
- Set `msDS-SupportedEncryptionTypes` on service and user accounts to AES128/AES256, then reset their passwords so AES keys exist.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; KERBEROS_WEAK_ETYPE must no longer be reported for those replies.
