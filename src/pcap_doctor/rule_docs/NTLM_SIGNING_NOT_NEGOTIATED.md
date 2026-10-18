# NTLM_SIGNING_NOT_NEGOTIATED

## What it means
The server's NTLM CHALLENGE message does not set NTLMSSP_NEGOTIATE_SIGN (0x00000010), so the authenticated session will not carry message signatures.

## Why it matters
Without signing an on-path attacker can relay the authentication or modify the traffic that follows it.

## How to fix
- Require NTLM message signing on servers and clients (Windows: "Microsoft network server: Digitally sign communications (always)" and "Network security: Require NTLM message signing"), or move to Kerberos.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; NTLM_SIGNING_NOT_NEGOTIATED must no longer be reported for those challenges.
