# TLS_SERVER_CIPHER_PREFERENCE

## What it means
The server chose a cipher suite that is **not** the first suite in the client's
ClientHello cipher list. In TLS the server always selects from the client's
offered list, but it can iterate that list in either of two orders:

- **client order** (OpenSSL default, `SSL_OP_CIPHER_SERVER_PREFERENCE` off): the server walks the client's list and picks the first suite it supports.
- **server order** (`SSL_OP_CIPHER_SERVER_PREFERENCE` / `CipherString` set): the server walks its own configured list and picks the first suite the client also offers.

When the chosen suite is not the first in the client's list, the server is
imposing its own preference rather than honouring the client's ordering.

## Why it matters
With client-order selection the client's preference always wins, so a client
that lists only strong suites is safe even if the server would otherwise prefer
a weaker one. With server-order selection the server's preference wins, which
can silently downgrade a connection when the server's list is weaker than the
client's top choice. A server that picks a non-first suite is operating in
server-preference mode and its own ordering rules the choice.

## How to fix
Decide on the desired policy:

- If you want clients to drive the cipher choice, disable cipher-server-preference
  (OpenSSL: remove the `CipherString` server preference or clear
  `SSL_OP_CIPHER_SERVER_PREFERENCE`; nginx: `ssl_prefer_server_ciphers off`).
- If you want the server to drive the choice, ensure the server's cipher list
  only contains suites you are willing to accept -- the server preference then
  cannot downgrade a client that offered strong suites.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`. With the
desired configuration the ServerHello cipher suite should be the first suite in
the ClientHello cipher list; `TLS_SERVER_CIPHER_PREFERENCE` is no longer
reported.
