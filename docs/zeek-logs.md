# Zeek-style logs

`pcap-doctor logs CAPTURE [-o DIR] [--format tsv|json|both] [--only conn,dns,...]` writes per-protocol logs with
Zeek's column names and types, so `zeek-cut`, Brim and SIEM parsers read them. `--format tsv` is Zeek's own file
(`#separator`, `#fields`, `#types`, `-` for unset, `(empty)`, `,` inside sets and vectors); `json` is one object
per line with unset fields left out. Every table is also a query source: `pcap-doctor query CAPTURE EXPR -s log:conn`.

| Log | One row per | Built from |
|---|---|---|
| `conn` | TCP/UDP connection, originator = first sender | `conn` pass (flags, lengths) |
| `dns` | query, with its answers, TXT/MX/NS/PTR/SRV/SOA/CAA answers and rcode | `dns` pass |
| `http` | request/response exchange | `http` pass |
| `ssl` | TLS/DTLS session: version, cipher name, SNI, ALPN, JA5/JA5S, JA5/JA5S, certificate ids, `validation_status` (openssl at capture time, `--ca-bundle` to pin a trust store), `hostname_match` | `tls` pass |
| `x509` | certificate in a handshake | `tls` pass |
| `files` | HTTP body that names a type or a file | `http` pass |
| `notice` | pcap-doctor finding (`note` = finding code) | the detectors |
| `weird` | tshark expert warning or error (malformed packet, bad length...) | `weird` pass |
| `dhcp` | DHCP transaction (xid) | `dhcp` pass |
| `ftp` | FTP command and its reply | `ftp` pass |
| `smtp` | mail transaction (`MAIL FROM` ... `QUIT`) | `smtp` pass |
| `ssh` | SSH session: banners and the first-offered algorithms | `ssh` pass |
| `smb` | SMB/SMB2 command or response, tree, file name, NTLM user | `smb` pass |
| `kerberos` | AS/TGS request with its reply or KRB-ERROR: client, service, error, ticket cipher (no key material) | `kerberos` pass |
| `ntlm` | NTLM AUTHENTICATE: user, workstation, domain, server names from the CHALLENGE (no responses) | `ntlm` pass |
| `modbus` | Modbus/TCP reply: function and exception name | `modbus` pass |
| `dnp3` | DNP3 request with its reply: function codes and IIN bits | `dnp3` pass |
| `tunnel` | encapsulation seen: GRE, VXLAN, GENEVE, GTP, MPLS, ERSPAN, PPPoE by outer endpoints (802.1Q as `VLAN`, an extension) | `tunnel` pass |
| `device` | one row per sender MAC: OUI vendor, IPs seen, packet count (an extension; Zeek's known_devices is similar) | `device` pass |
| `protocols` | protocol hierarchy breakdown: frames, bytes and share of frames per protocol layer (an extension, like `tshark -z io,phs` flattened) | `protocols` pass |

## Where the logs differ from Zeek

- `conn.orig_bytes` / `resp_bytes` are TCP/UDP payload bytes seen in the capture (no sequence-number accounting, so a
  retransmission counts twice); `*_ip_bytes` are IP total lengths; `missed_bytes` adds up the sequence-number jumps
  tshark marks as a lost segment (#208).
- `history` is approximated from the SYN/ACK/data/FIN/RST flags (upper case originator, lower case responder; runs of
  the same letter collapse), plus Zeek's `C` bad checksum, `G` content gap, `T` retransmission and `W` zero window,
  logged at their 1st, 10th, 100th... occurrence (#208, #209). Two extra columns at the end, `dup_acks` and
  `out_of_order`, count tshark's duplicate-ACK and out-of-order marks; Zeek has no such columns. `conn_state` follows Zeek's definitions (`S0`, `S1`, `SF`, `REJ`, `RSTO`, `RSTR`, `S2`,
  `S3`, `RSTOS0`, `OTH`) from the same counts.
- `uid` is `C` plus 16 hex characters derived from the flow key, stable across runs, not Zeek's random id.
- Secrets are never written: FTP `PASS` is `<hidden>`, no HTTP Authorization or cookie values, no SMTP AUTH data.
- `weird` names are slugs of tshark's own expert messages, not Zeek's weird names (see the table below),
  except bad checksums, which use Zeek's `bad_IP_checksum` / `bad_TCP_checksum` / `bad_UDP_checksum` /
  `bad_ICMP_checksum`. Checksums are validated for the conn and weird logs only; captures taken on the sending host
  with checksum offload show every outgoing packet as bad.

  | tshark expert message starts with | Zeek weird |
  |---|---|
  | `Bad length value` | `UDP_datagram_length_mismatch` |
  | `Bogus TCP Header length` | `bad_TCP_header_len` |
  | `Window scale shift exceeds 14` | `TCP_scale_range` |
  | `The Content-Length and Transfer-Encoding header must not be set together` | `HTTP_content_length_and_chunked` |
  | `Bad checksum` (IP) | `bad_IP_checksum` |
  | `Bad checksum` (TCP) | `bad_TCP_checksum` |
  | `Bad checksum` (UDP) | `bad_UDP_checksum` |
  | `Bad checksum` (ICMP) | `bad_ICMP_checksum` |
- `files` lists the files `extract` recovers, with `seen_bytes`, `md5`, `sha1`, `sha256` and a magic-byte `mime_type`; only HTTP files carry hosts and a connection uid.
- `#open` / `#close` carry the capture's first and last packet time, so two runs give identical files.
- `dns.answers` holds A/AAAA/CNAME/MX/NS/PTR/SRV-target/SOA-mname values as they are, TXT as `TXT <len> <text>` and CAA as `<tag> <value>`; an extra last column `edns_udp_size` gives the query's EDNS payload size (#229).
