# HTTP_WEB_ATTACK_LFI

## What it means
An HTTP request URI contains a local file inclusion payload, such as a `php://filter` wrapper, a `file://` scheme, or a reference to a sensitive system file like `/etc/passwd` or `/etc/shadow`.

## Why it matters
If the parameter is used to include or read a file on the server without validation, the attacker can read sensitive files, configuration, or source code, and in some cases achieve remote code execution.

## How to fix
- Deny user-controlled path segments entirely.
- Map requests to a fixed allow-list of files rather than including from user input.
- Disable dangerous PHP wrappers (`php://`, `file://`) and validate that the resolved path stays inside an allowed root.

## How to verify
Confirm the server rejects or sanitises path-like input; capture the same traffic again and run `pcap-doctor analyze <capture>`; `HTTP_WEB_ATTACK_LFI` must not be reported.
