# Zeek-style logs

`pcap-doctor logs CAPTURE [-o DIR] [--format tsv|json|both] [--only conn,dns,...]` writes per-protocol logs with
Zeek's column names and types, so `zeek-cut`, Brim and SIEM parsers read them. `--format tsv` is Zeek's own file
(`#separator`, `#fields`, `#types`, `-` for unset, `(empty)`, `,` inside sets and vectors); `json` is one object
per line with unset fields left out. Every table is also a query source: `pcap-doctor query CAPTURE EXPR -s log:conn`.

| Log | One row per | Built from |
|---|---|---|
| `conn` | TCP/UDP connection, originator = first sender | `conn` pass (flags, lengths) |
| `known_services` | each server host, the ports it serves and the service name (Zeek known_services) | from flows |
| `dns` | query, with its answers, TXT/MX/NS/PTR/SRV/SOA/CAA/SVCB/HTTPS/RRSIG/DNSKEY/DS/NSEC/NSEC3 answers and rcode | `dns` pass |
| `http` | request/response exchange | `http` pass |
| `ssl` | TLS/DTLS session: version, cipher name, SNI, ALPN, JA5/JA5S, JA5/JA5S, certificate ids, `validation_status` (openssl at capture time, `--ca-bundle` to pin a trust store), `hostname_match` | `tls` pass |
| `x509` | certificate in a handshake, including its fingerprint (SHA-256 of the DER; the certificate is exported as `certificates/<fingerprint>.pem`) | `tls` pass |
| `files` | HTTP body that names a type or a file | `http` pass |
| `notice` | pcap-doctor finding (`note` = finding code) | the detectors |
| `weird` | tshark expert warning or error (malformed packet, bad length...) | `weird` pass |
| `expert` | every Wireshark expert-info item: severity (comment, chat, note, warn, error), group and message (an extension; `weird` keeps only warn and error) | `weird` pass |
| `dhcp` | DHCP transaction (xid) | `dhcp` pass |
| `netbios` | NBNS/NetBIOS name queried on the wire, with the address(s) the responder returned and the group flag from the NB flags | `netbios` pass |
| `dhcpv6` | DHCPv6 exchange (transaction id, client DUID/MAC, IAID, assigned IPv6, DNS, FQDN, vendor class) | `dhcpv6` pass |
| `ftp` | FTP command and its reply | `ftp` pass |
| `smtp` | mail transaction (`MAIL FROM` ... `QUIT`) | `smtp` pass |
| `ssh` | SSH session: banners and the first-offered algorithms | `ssh` pass |
| `smb` | SMB/SMB2 command or response, tree, file name, NTLM user | `smb` pass |
| `kerberos` | AS/TGS request with its reply or KRB-ERROR: client, service, error, ticket cipher (no key material) | `kerberos` pass |
| `ntlm` | NTLM AUTHENTICATE: user, workstation, domain, server names from the CHALLENGE (no responses) | `ntlm` pass |
| `modbus` | Modbus/TCP reply: unit id, function and exception name | `modbus` pass |
| `dnp3` | DNP3 request with its reply: DNP3 source and destination addresses, function codes and IIN bits | `dnp3` pass |
| `rfb` | RFB/VNC handshake: protocol version, security types offered and selected, auth result, desktop name | `vnc` pass |
| `stun` | one row per STUN message: message type (method) and the XOR-MAPPED-ADDRESS (family, IP, port) when present | `stun` pass |
| `rtsp` | one row per RTSP request with its response: method, URL and status | `rtsp` pass |
| `mqtt` | MQTT control packet (first one per TCP segment; message type is tshark's value string, e.g. `Publish Message`): version, message type, client id, user name, topic, CONNACK return code (no password) | `mqtt` pass |
| `enip` | EtherNet/IP encapsulation packet: command, session handle, status, CIP service (request or reply), CIP class; command and service names are tshark's value strings, unlisted codes are numbers | `enip` pass |
| `iec104` | IEC 60870-5-104 APDU (first per segment): frame type I/S/U, U function, ASDU type, cause of transmission, common address and IOA; names are tshark's value strings | `iec104` pass |
| `bacnet` | BACnet/IP APDU: BVLC function, APDU type, service choice and invoke id; names are tshark's value strings | `bacnet` pass |
| `s7comm` | S7comm PDU: ROSCTR, function, item count, memory area and DB of the first item (no data values); names are tshark's value strings | `s7comm` pass |
| `opcua` | OPC UA binary transport message: HEL, ACK, OPN, MSG or CLO, and the service it carries (request or response, tshark's service names); no payload values | `opcua` pass |
| `tunnel` | encapsulation seen: GRE, VXLAN, GENEVE, GTP, MPLS, ERSPAN, PPPoE by outer endpoints (802.1Q as `VLAN`, an extension) | `tunnel` pass |
| `bittorrent` | BitTorrent DHT messages (query type — ping, find_node, get_peers, announce_peer — transaction id and, for get_peers/announce_peer, the info_hash as hex) and peer-wire handshakes (info_hash and peer-id version prefix), parsed from the bt-dht heuristic dissector and the handshake | `bt-dht` pass |
| `device` | one row per sender MAC: OUI vendor, IPs seen, packet count (an extension; Zeek's known_devices is similar) | `device` pass |
| `software` | versioned software from HTTP Server / User-Agent headers and SSH banners (Zeek software.log: HTTP::SERVER, HTTP::BROWSER, SSH::SERVER, SSH::CLIENT) | `software` pass |
| `os` | passive OS-family guess per host from the initial TTL of its SYNs (p0f-style, TTL only: 64 Linux/Unix/Android/macOS, 128 Windows, 255 network device) | `os` pass |
| `protocols` | protocol hierarchy breakdown: frames, bytes and share of frames per protocol layer (an extension, like `tshark -z io,phs` flattened) | `protocols` pass |
| `syslog` | one row per syslog message over UDP/514, RFC 3164 and RFC 5424: facility, severity, version, timestamp text, hostname, app/tag, process id, message id and the message text (truncated to 200 chars) | `syslog` pass |
| `capture_loss` | ACKs, gaps (segments after a mid-stream hole) and percent lost, like Zeek's capture_loss.log | `capture_loss` pass |
| `conversations` | frames, bytes, first seen and duration per IP pair, both directions together (an extension, like `tshark -z conv,ip`) | `frames` pass |
| `io` | frames and bytes per one-second bucket (an extension, like Wireshark's IO graph) | `frames` pass |
| `rdp` | RDP negotiation: security protocol (RDP/TLS/CredSSP), flags, client cookie (mstshash) and client name | `rdp` pass |

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
- `dns.answers` holds A/AAAA/CNAME/MX/NS/PTR/SRV-target/SOA-mname values as they are, TXT as `TXT <len> <text>` and CAA as `<tag> <value>`, SVCB/HTTPS as their target name, RRSIG as the signer's name, DNSKEY as the key tag, DS as the key tag, NSEC as the next domain name and NSEC3 as the next hashed owner name; an extra last column `edns_udp_size` gives the query's EDNS payload size (#229).
