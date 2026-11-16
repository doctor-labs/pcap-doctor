# NTLM_NEGOTIATION

## What it means
An NTLMSSP NEGOTIATE message was observed, indicating an NTLM authentication exchange on the flow. The finding reports negotiated/observable properties (including an inferred hash algorithm class based on response length when present) and never includes challenges, responses, or hash material.

## Why it matters
NTLM negotiation reveals where legacy authentication is still in use and which exchanges may expose crackable or relayable material. Visibility into negotiation helps prioritize hardening and migration to Kerberos.

## How to fix
- Prefer Kerberos over NTLM wherever possible.
- Where NTLM is required, enforce NTLMv2 only, require signing and EPA/channel binding, and restrict NTLM to necessary hosts.

## How to verify
Capture the same workflow again and confirm NTLM is no longer negotiated, or that only hardened NTLMv2-protected exchanges remain as intended.
