# NTLM_HASH_OFFLINE_CRACKABLE

## What it means
An NTLM AUTHENTICATE message contains a 24-byte NT response length, indicating NTLMv1 challenge-response material is present on the wire. The finding reports lengths, account/domain, and frames only and never prints response or challenge bytes.

## Why it matters
NTLMv1 responses are weak and can be cracked offline or abused in relay/replay scenarios to recover or misuse credential material. Presence of this material on the network is a high-risk exposure even when the raw bytes are not shown in reports.

## How to fix
- Disable NTLMv1: set "LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" on clients and servers.
- Upgrade or retire systems that require NTLMv1.
- Rotate credentials for affected accounts and move authentication to Kerberos where possible.

## How to verify
Capture the same traffic after hardening and confirm no 24-byte NTLMv1 responses are observed. `pcap-doctor analyze <capture>` should no longer report `NTLM_HASH_OFFLINE_CRACKABLE` or `NTLM_V1_AUTH`.
