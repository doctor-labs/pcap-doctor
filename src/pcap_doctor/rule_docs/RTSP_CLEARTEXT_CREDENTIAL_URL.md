# RTSP_CLEARTEXT_CREDENTIAL_URL

## What it means
An RTSP request URL in the capture contains user information (credentials) embedded in the URL.

## Why it matters
Credentials placed in URLs are transmitted in cleartext, may be stored in logs, proxies, browser history, or monitoring systems, and can be trivially captured by anyone on the network path. This enables account compromise and unauthorised access to media streams.

## How to fix
Remove credentials from RTSP URLs immediately and rotate any exposed secrets. Use proper authentication mechanisms (for example digest authentication or token-based access) over a protected channel such as RTSPS/TLS.

## How to verify
Recapture traffic and confirm RTSP URLs no longer contain user information. Validate that rotated credentials are required and that old credentials no longer grant access.
