# TLS_NO_SCT

## What it means

The leaf TLS certificate presented by the server does not carry the
Certificate Transparency `SignedCertificateTimestampList` extension — OID
`1.3.6.1.4.1.11129.2.4.2` (RFC 6962 section 6.1). That extension holds one or
more Signed Certificate Timestamps (SCTs), which are cryptographic promises
from CT logs that the certificate was logged.

Without SCTs the certificate is not covered by CT auditing at all. It may still
be a valid certificate that chains to a trusted root; the finding only notes
that the transparency layer is absent.

## Why it matters

Certificate Transparency exists so that misissuance is detectable: browsers and
monitors can watch the public log and sound an alarm when a certificate for a
name they don't expect appears. A certificate without SCTs bypasses that
detection net entirely — an attacker who compromises a CA, or a CA that issues
without logging, can hand out certificates that will never appear in a CT log.

Chrome, Safari and Firefox rely on CT for most publicly-trusted certificates
(Chrome's CT policy requires SCTs for most leaf certificates issued after
April 2021). A server that serves a certificate with no SCTs either uses a CA
that does not embed them, or a self-signed/internal certificate — both worth
confirming.

## How to fix

- Reissue the certificate through a CA that embeds SCTs. The CA/Browser Forum
  baseline requirements effectively require SCTs for publicly-trusted
  certificates, so a CA that skips them is non-compliant.
- If using a private/internal CA, add SCTs at the load balancer by configuring
  it to send the TLS `signed_certificate_timestamp` extension (extension type
  18, RFC 6962 section 6.1) on the certificate message.
- For a self-signed certificate used only internally: CT does not apply;
  suppress or document this finding.

## How to verify

Inspect the certificate with openssl:

```sh
openssl x509 -in cert.pem -noout -text | grep -i "SCT\|11129"
```

A certificate with SCTs prints:

```
CT Precertificate SCTs:
```

A certificate without them has no such line. The OID `1.3.6.1.4.1.11129.2.4.2`
can also be confirmed via:

```sh
openssl asn1parse -in cert.pem -inform PEM | grep -i "11129\|Precertificate"
```

With tshark:

```sh
tshark -r capture.pcap -Y "x509ce.id == 1.3.6.1.4.1.11129.2.4.2"
```
