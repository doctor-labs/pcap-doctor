# HTTP2_CLEARTEXT

## What it means
An HTTP/2 conversation crossed the network in cleartext (h2c, prior-knowledge) over TCP. The client connected and immediately spoke the HTTP/2 connection preface (`PRI * HTTP/2.0`) and HEADERS frames, so neither peer negotiated TLS. The `:method`, `:path`, `:authority` and `:status` pseudo-headers were decoded from the HPACK header block.

## Why it matters
Without TLS, an HTTP/2 stream is no more protected than plain HTTP/1.1: request URLs, pseudo-headers, header fields and the body are all readable and modifiable on the network path. HTTP/2 offers no confidentiality of its own, so any credential, cookie, token or API call carried in cleartext can be read or replayed by an on-path observer. A firmware download over h2c is additionally at risk of substitution (CWE-494) if the image is not integrity-checked by the device.

## How to fix
- Serve HTTP/2 only behind TLS (h2 over TLS); advertise it with ALPN (`h2`) so clients upgrade to the encrypted profile.
- If an API must run without TLS inside a trusted network, do not carry credentials, tokens or sensitive payloads in it, and require an out-of-band integrity check (signature, MAC) on any downloaded artifact.
- Remove the prior-knowledge h2c listener, or gate it behind a network segmentation control that prevents untrusted clients from reaching it.

## How to verify
Capture the traffic again and run `pcap-doctor analyze <capture>`; HTTP2_CLEARTEXT must not be reported and the flow in `01-flows.md` must show as encrypted. Inside TLS, tshark's `http2` dissector shows the same pseudo-headers but the flow is reported as `tls`, and this finding does not fire.
