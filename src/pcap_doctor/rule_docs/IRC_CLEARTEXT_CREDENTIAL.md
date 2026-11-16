# IRC_CLEARTEXT_CREDENTIAL

## What it means
An IRC credential was sent in cleartext: a PASS command, an OPER command, a NickServ IDENTIFY message, or a channel JOIN carrying a key. The finding names the protocol, the account or target, and the frame where it was seen; the secret value itself is redacted.

## Why it matters
Anyone on the network path can capture the credential and reuse it to take over the IRC account, gain operator privileges, or join protected channels.

## How to fix
- Rotate the exposed IRC password or channel key immediately.
- Use IRC over TLS (typically port 6697) and avoid sending credentials on plain IRC connections.
- Restrict operator access and use strong, unique secrets.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; IRC_CLEARTEXT_CREDENTIAL must not be reported.
