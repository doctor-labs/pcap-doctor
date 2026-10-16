# HTTP_MISSING_SECURITY_HEADERS

## What it means
An observed HTTP response was seen carrying none or some of the recommended security response headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options and X-Frame-Options. Only cleartext HTTP exchanges (responses with a status code, over an unencrypted flow) are reported.

## Why it matters
Missing security headers leave users exposed to downgrade and man-in-the-middle attacks (no HSTS), cross-site scripting and content injection (no CSP), MIME-type sniffing confusion (no X-Content-Type-Options) and clickjacking (no X-Frame-Options). Because the response is cleartext, anyone on the path can read or alter it, so the missing defences compound the exposure.

## How to fix
- Add Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff and X-Frame-Options (or a frame-ancestors CSP directive) to every HTTP response that is meant to be served.
- Prefer migrating the endpoint to HTTPS so HSTS applies to real browser traffic; the headers alone do not secure a cleartext capture.
- For non-browser responses (APIs, firmware downloads), X-Frame-Options and CSP framing controls are irrelevant; still apply X-Content-Type-Options and HSTS where applicable.

## How to verify
Re-run `pcap-doctor analyze <capture>` after the server is reconfigured. HTTP_MISSING_SECURITY_HEADERS must no longer be reported for exchanges whose response now carries the required headers.
