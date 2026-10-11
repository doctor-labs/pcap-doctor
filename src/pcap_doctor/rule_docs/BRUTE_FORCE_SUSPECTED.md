# BRUTE_FORCE_SUSPECTED

## What it means
A single client repeatedly failed logins against one server and service (FTP 530, HTTP 401 with credentials, or SMB 0xc000006d) at a count that exceeds the detector's threshold for that service.

## Why it matters
The repeated failed attempts match the shape of password guessing or credential stuffing. If any of those attempts later succeeded, the targeted account may be compromised.

## How to fix
- Lock out or rate-limit repeated failed logins on the server.
- Confirm whether any login from the client succeeded, and investigate that session.
- Block or throttle the source client if the activity is not expected.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; BRUTE_FORCE_SUSPECTED must no longer be reported once the repeated failed logins stop.
