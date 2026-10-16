# HTTP_WEB_ATTACK_COMMAND_INJECTION

## What it means
An HTTP request URI contains an OS command injection payload, such as a command separator followed by a shell command (`;cat /etc/passwd|sh`), command substitution `$(...)`, or backticks.

## Why it matters
If the parameter is passed to a shell or command-execution API on the server, the attacker can execute arbitrary operating-system commands, leading to full host compromise, data exfiltration, or lateral movement.

## How to fix
- Avoid invoking a shell with user input; pass arguments as a list to `exec`-family APIs.
- Reject or escape shell metacharacters (`;`, `|`, `&`, `$`, backticks).
- Validate input against a strict allow-list of expected values.

## How to verify
Confirm the server treats the metacharacters as data, not as command separators; capture the same traffic again and run `pcap-doctor analyze <capture>`; `HTTP_WEB_ATTACK_COMMAND_INJECTION` must not be reported.
