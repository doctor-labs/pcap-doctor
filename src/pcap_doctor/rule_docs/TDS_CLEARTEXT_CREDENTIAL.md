# TDS_CLEARTEXT_CREDENTIAL

## What it means
A Microsoft SQL Server TDS LOGIN7 packet carried credentials in the clear (before encryption is established). The finding names the protocol, the account, and the frame where it was seen; the password value itself is redacted.

## Why it matters
Anyone on the network path can capture the login credentials and use them to access the database, read or modify data, or pivot further.

## How to fix
- Rotate the exposed database credentials immediately.
- Require encrypted TDS connections (force encryption on the server and clients) so LOGIN7 is protected by TLS.
- Disable or restrict unencrypted logins and review network exposure of SQL Server.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TDS_CLEARTEXT_CREDENTIAL must not be reported.
