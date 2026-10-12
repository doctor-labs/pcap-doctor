# HTTP_WEB_ATTACK_SQLI

## What it means
An HTTP request URI contains a SQL injection payload, such as a tautology (`OR 1=1`), a `UNION SELECT`, or a comment terminator (`--` or `#`) appended to a parameter value.

## Why it matters
If the targeted parameter is concatenated into a server-side SQL query without parameterisation, the attacker can read or modify database contents, bypass authentication, or in some cases execute commands on the host.

## How to fix
- Use parameterised queries / prepared statements or an ORM that binds parameters safely.
- Validate input against a strict allow-list of expected values and types.
- Reject or escape raw quotes and SQL comment syntax in parameters.

## How to verify
Reproduce the request with the payload removed or with bind parameters and confirm it is handled safely; capture the same traffic again and run `pcap-doctor analyze <capture>`; `HTTP_WEB_ATTACK_SQLI` must not be reported.
