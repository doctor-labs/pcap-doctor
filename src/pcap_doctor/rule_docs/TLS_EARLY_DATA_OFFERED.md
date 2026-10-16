# TLS_EARLY_DATA_OFFERED

## What it means
The ClientHello on this TLS 1.3 session contains the `early_data` extension (type 42), as defined by RFC 8446 section 4.2.10. The client is offering to send 0-RTT (zero round-trip time) data, which means the client may send application data before the handshake completes -- before the server has confirmed the client's identity or before a fresh handshake key is established.

## Why it matters
0-RTT data is replayable: a MITM or a captured 0-RTT record can be replayed against the server, and the server must protect against this at the application layer. 0-RTT keys are also derived from the PSK of a previous session, so they are not forward secret against an attacker who later obtains the PSK. This is a property of the protocol, not a bug in the implementation, but it changes the threat model for any data sent in 0-RTT.

## How to fix
- Ensure any 0-RTT data is idempotent and safe to replay.
- See RFC 8446 section 8 for replay mitigation guidance.
- Disable 0-RTT (set `max_early_data_size` to 0, or configure the server/client to reject 0-RTT) if the application cannot tolerate replay.
- Remember that 0-RTT is optional: the server's acceptance is signaled separately by `tls.early_data.max_early_data_size` in the EncryptedExtensions.

## How to verify
Capture TLS 1.3 traffic where the client offers early data and run `pcap-doctor analyze <capture>`. `TLS_EARLY_DATA_OFFERED` is reported when the ClientHello carries the `early_data` extension (type 42). The server's acceptance is reported by the `max_early_data_size` field in the EncryptedExtensions, which a full analysis can cross-reference.
