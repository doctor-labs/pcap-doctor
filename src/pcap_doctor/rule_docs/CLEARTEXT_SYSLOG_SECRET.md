# CLEARTEXT_SYSLOG_SECRET

## What it means
A syslog message appears to contain a credential- or token-like field (such as password, token, secret or authorization text) and was observed in cleartext.

## Why it matters
Secrets in logs can be harvested by anyone who can observe or collect the log stream, leading to account compromise or lateral movement.

## How to fix
- Remove credentials and tokens from log messages and rotate any exposed secret.
- Ship logs over an encrypted transport and limit who can read collected logs.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_SYSLOG_SECRET must be absent after redacting sensitive fields and rotating exposed secrets.
