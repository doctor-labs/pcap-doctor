# TLS_INSECURE_RENEGOTIATION

## What it means
The negotiated version is TLS 1.0, 1.1 or 1.2, both a ClientHello and ServerHello are present, and the ServerHello does not contain the renegotiation_info extension (type 65281, RFC 5746).

## Why it matters
Without the renegotiation_info extension, the server does not support RFC 5746 secure renegotiation, leaving the session open to a man-in-the-middle splicing a prefix into a renegotiated session (CVE-2009-3555). If the client offered the renegotiation SCSV cipher value 0x00FF and the server ignored it, the server is not only missing secure renegotiation but also failed to use the fallback cipher-suite signal that would at least block prefix injection.

## How to fix
- Enable RFC 5746 secure renegotiation on the server (e.g. `ssl_verify_client_cert` / `secure_renegotiation` options in OpenSSL, `SecureRenegotiation` in IIS).
- If renegotiation is not needed, disable it entirely.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_INSECURE_RENEGOTIATION must not be reported once the ServerHello contains extension type 65281 (or the session moves to TLS 1.3). You can inspect the ServerHello extensions directly: `tshark -r <capture> -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.extension.type`.
