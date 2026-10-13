# TLS_ECH_OFFERED

## What it means
The ClientHello on this TLS session contains the Encrypted Client Hello (ECH) extension (type `0xfe0d` / 65037), as defined by RFC 9849. The client is attempting to encrypt the inner ClientHello, including the SNI, from passive observers.

## Why it matters
ECH is a privacy improvement: it hides the server name and other inner ClientHello extensions from passive network observers. A passive analysis tool like pcap-doctor cannot decrypt the inner ClientHello, so the SNI and extension set seen at the outer layer may be incomplete. This finding tells the analyst that ECH is in use and that outer-layer inspection is limited.

## How to fix
No action required: ECH is a recommended privacy feature. If you need to see the full inner ClientHello, deploy with access to the server's ECH private key and use a 0-RTT-capable keylog or decryption configuration.

## How to verify
Capture TLS traffic to a server that supports ECH and run `pcap-doctor analyze <capture>`. `TLS_ECH_OFFERED` is reported when the ClientHello carries the ECH extension. The confirmation or rejection of ECH by the server is signalled separately by tshark fields `tls.ech_accepted` / `tls.ech_rejected`.
