# NTLM_V1_AUTH

## What it means
An NTLM AUTHENTICATE message carries a 24-byte response, which is the NTLMv1 format. The finding reports the frame and the response length only; the response itself is never printed.

## Why it matters
NTLMv1 responses are weak: they can be cracked, and with a known challenge they can be replayed to recover the NT hash. NTLMv1 offers no protection against an on-path attacker.

## How to fix
- Set "LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" on clients and servers.
- Find the clients that still send NTLMv1 and upgrade them, or retire them.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; NTLM_V1_AUTH must no longer be reported.
