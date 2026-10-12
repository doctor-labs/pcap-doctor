# HTTP_WEB_ATTACK_XSS

## What it means
An HTTP request URI contains a cross-site scripting payload such as a `<script>` tag, a `javascript:` URI, or an inline event-handler attribute (`onerror=`, `onload=`, etc.).

## Why it matters
If the URI is reflected verbatim into an HTML response without encoding, the script executes in the victim's browser, enabling session theft, credential capture, or actions performed as the victim.

## How to fix
- Context-encode all user input on output (HTML, attribute, JavaScript, and URL encoding as appropriate).
- Enforce a strict Content-Security-Policy that blocks inline scripts.
- Set the `HttpOnly` and `Secure` flags on cookies.

## How to verify
Render the response and confirm the payload is encoded, not executed; capture the same traffic again and run `pcap-doctor analyze <capture>`; `HTTP_WEB_ATTACK_XSS` must not be reported.
