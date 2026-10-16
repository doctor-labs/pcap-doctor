# HTTP_WEB_ATTACK_TRAVERSAL

## What it means
An HTTP request URI contains a path traversal pattern — two or more `../` sequences — that escapes the intended document root.

## Why it matters
If the server resolves the URI to a filesystem path without normalisation, the attacker can read files outside the web root, such as `/etc/passwd`, `/etc/shadow`, or application configuration and source files.

## How to fix
- Normalise and canonicalise all paths before use.
- Reject or strip `..` segments and any path that resolves outside the fixed document root.
- Map requests to a fixed root directory and verify the final path is contained within it.

## How to verify
Confirm the server returns 403 or a safe redirect for path-traversal payloads; capture the same traffic again and run `pcap-doctor analyze <capture>`; `HTTP_WEB_ATTACK_TRAVERSAL` must not be reported.
