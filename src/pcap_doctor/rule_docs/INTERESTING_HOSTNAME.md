# INTERESTING_HOSTNAME

## What it means
A hostname whose first label looks like an admin, login or sign-in panel (for example `login`, `admin-panel`, `signin`, `wp-admin`) was observed in cleartext in this capture: in a DNS query, a TLS Server Name Indication (SNI) extension, or an HTTP `Host` header.

## Why it matters
The name of a sensitive panel is itself sensitive: any on-path observer who sees it can target that exact address. DNS over cleartext, plaintext SNI and cleartext HTTP Host headers each leak the hostname independently, and the leak is not limited to the resolver or the web server. This mirrors what Zeek reports as `Interesting_Hostname_Login` and `External_Name`.

## How to fix
- Move sensitive panels behind private DNS / VPN names and do not expose them in publicly resolvable zones.
- Use encrypted DNS (DNS-over-TLS port 853 or DNS-over-HTTPS) so the query name is hidden from the path.
- Deploy TLS Encrypted Client Hello (ECH) so the SNI is encrypted, or terminate TLS at a reverse proxy that does not carry the customer-facing panel name in cleartext.
- Serve the panel only over HTTPS and ensure internal-facing panels are not reachable from the network where this capture was taken.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`. `INTERESTING_HOSTNAME` must not be reported for any hostname whose first label is not a login/admin/sign-in surface, and must be absent when no sensitive hostname is queried, negotiated or requested.
