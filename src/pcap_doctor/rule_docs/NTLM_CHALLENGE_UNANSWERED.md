# NTLM_CHALLENGE_UNANSWERED

## What it means
The server sent an NTLMSSP CHALLENGE but no NTLMSSP AUTHENTICATE message followed on the same flow. The finding reports the challenge frame only; no challenge bytes or hash material are included.

## Why it matters
An unanswered challenge can indicate NTLM probing, coercion/relay setup attempts, or a client declining to complete NTLM authentication. It is a useful signal when investigating suspicious authentication traffic.

## How to fix
- Investigate the source and destination of the unsolicited or incomplete NTLM exchange.
- Disable NTLM where possible; require Kerberos, NTLMv2, signing, and EPA/channel binding where NTLM remains.
- Alert on unexpected NTLM challenges and authentication coercion techniques.

## How to verify
Reproduce the scenario and confirm either legitimate NTLM completion or that unsolicited challenges no longer occur. The finding should clear when no unanswered challenges are present.
