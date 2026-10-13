# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Added the ICS_CONTROL_COMMAND detector (d20.ics_control): cleartext Modbus write, DNP3 control, S7comm Write Var and IEC 60870-5-104 command activations (#206).

### Changed

- **Rename finished.** The internal import package is now `pcap_doctor` (was `pcapforensics`): `python -m pcap_doctor.cli`,
  `from pcap_doctor import ...`. The pip distribution, the `pcap-doctor` command, the `pf` alias and the doctor/1 tool id are
  unchanged. All GitHub URLs, badges and the Action reference now point to `doctor-labs/pcap-doctor`
  (`uses: doctor-labs/pcap-doctor@v...`). `PCAP_FORENSICS_CACHE` is still honoured.

### Added

- `pcap-doctor search CAPTURE PATTERN`: keyword / byte-pattern search across packet payloads (TCP and UDP data, reassembled per frame). A literal text keyword by default, or a hex byte string with `--hex` (e.g. `deadbeef`); matches print with frame, protocol, direction, endpoint, offset, length and a hex snippet, and `--json` emits the same shape for CI gating. Exits 1 when nothing matches, 0 otherwise (#215).
- `extract` writes plain IRC chat (ports 6660-6669) as one transcript per conversation: every PRIVMSG and NOTICE with its frame number, lines split across TCP segments joined, TLS IRC on 6697 not read. Email (SMTP, IMAP, POP3) was already extracted (#202). (#213)
- **RDP keystrokes and screen (#217).** `pcap-doctor rdp CAPTURE` lists the keys typed and the last screen (uncompressed 16/32-bit bitmaps) of plain RDP sessions on port 3389; TLS and CredSSP sessions are reported as encrypted, not rebuilt.
- `pcap-doctor vnc CAPTURE`: VNC (RFB 3.8) reconstruction (#217). Per session it lists the keys typed (keysyms as text, named keys like `<RET>`), the clipboard text, and the last screen as a PNG written to `CAPTURE.vnc/stream-N.png` (mode 0600). Covers the None and VNC-authentication security types (the DES password is not recovered; the session after it is cleartext), true-colour pixel formats and the Raw, CopyRect and DesktopSize encodings. Other encodings (RRE, Hextile, ZRLE, Tight...) stop the screen at that point and say so; keys and clipboard are still read. RDP is not handled. `--stream N` picks one TCP stream. Library: `pcap_doctor.vnc.parse_rfb`. No new findings.
- `opcua.log` (#206): one row per OPC UA binary transport message (HEL, ACK, OPN, MSG, CLO) with the service it carries, names from tshark's value strings.
- `s7comm.log` (#206): one row per S7comm PDU (ROSCTR, function, item count, memory area and DB), names from tshark's value strings.
- `bacnet.log` (#206): one row per BACnet/IP APDU (BVLC function, APDU type, service, invoke id), names from tshark's value strings.
- `iec104.log` (#206): one row per IEC 60870-5-104 APDU (I/S/U frame, U function, ASDU type, cause, common address, IOA), names from tshark's value strings.
- `enip.log` (#206): one row per EtherNet/IP encapsulation packet (command, session handle, status, CIP service and whether it is a reply, CIP class).
- `mqtt.log` (#206): one row per MQTT control packet (version, message type, client id, user name, topic, CONNACK return code); the password is never written.
- `pcap-doctor analyze --ioc FILE` (repeatable): local indicator matching for IPs/CIDRs, domains (and their subdomains) and http(s) URLs, one per line with an optional label. Matched against DNS names and answers, TLS SNI, HTTP Host/URI and observed hosts as `IOC_MATCH` (new detector `d21.ioc_match`, severity high, confidence medium). Opt-in and offline: the file is read from disk and nothing is fetched. Hash indicators (md5, sha1, sha256) are matched against the objects extracted from the capture (temp dir, bytes discarded after hashing) and reported as `IOC_MATCH` too. Still local-only. (#236)
- `analyze --geoip-db FILE` (or `PCAP_DOCTOR_GEOIP_DB`): an opt-in, offline GeoIP/ASN lookup from a CSV range file you supply (header `network,asn,as_name,country`, one CIDR per row). It sets each host's `asn_note` to e.g. `AS64500 EXAMPLE-NET, US`; hosts the file does not cover stay unset. Nothing is fetched from the network. The reader is stdlib-only, so no new dependency (#237).
- `pcap-doctor tabs CAPTURE --tab hosts|files|credentials` (#252, parity G-57): read-only host, file and credential views over the built index, with no extra tshark pass. Hosts show MAC, vendor, hostname, OS guess, roles and volume; files list HTTP download names and SMB file creates with their frame and flow; credentials list HTTP auth (redacted through `redact_auth`), Telnet logins (user and password length only) and SMB NTLM identities. The interactive key-driven tabs are not built yet; this is the data layer they will sit on (`pcap_doctor.browse_tabs`).
- Vulnerable software version inventory (#235): HTTP `Server`/`User-Agent` and SSH banners that fall in a short, curated list of known-vulnerable ranges raise `SERVICE_VULNERABLE_VERSION` (medium, medium confidence, with the CVE). Parity with Zeek `Vulnerable_Version`; detector `d22.software_vulns`. SMTP and FTP 220 greetings are inventoried too (Exim, ProFTPD, vsftpd) from the existing services pass.

- Notice framework (Zeek-style, #273): `[notice.CODE]` in the project config sets a per-code `action` (`report`, `log` to notes only, or `suppress`), `dedup = true` to keep one finding per code, flow and subject (worst severity wins), and `max = N` to rate-limit a code per run. Every effect is written to the report notes. Without a `[notice]` table nothing changes.
- `session` command: search sessions (flows) by endpoint, port, application protocol, TLS SNI or HTTP host (`session CAPTURE QUERY`, `--json`), and write one session's packets to a file with `session CAPTURE --key FLOW_KEY --out FILE`. Retrieval asks tshark for the session's `tcp.stream`/`udp.stream` on demand. (#251)
- `pcap-doctor ship CAPTURE` ships the EVE events (alert, flow, dns, http, tls, fileinfo) to a SIEM, opt-in only: `--out FILE` or stdout as JSON-lines (or `--format syslog`), `--syslog HOST:PORT --proto udp|tcp` as RFC 5424 syslog (TCP uses octet-counting), or `--http URL` as an `application/x-ndjson` POST. Stdlib only. A bearer token is read from the env var named by `--token-env` (default `PCAP_DOCTOR_SHIP_TOKEN`) and is never printed. Kafka is not built: it needs a client library (#257).
- `scripts/bench_large.py` and a fast regression guard `tests/test_launch_budget.py`: a repeatable large-capture benchmark (deterministic `mergecap` of N copies of a fixture, run through `analyze` with a tshark-launch counter that prints wall time, user+sys CPU seconds and peak child RSS) and a CI guard asserting the number of tshark pass launches (excluding `tshark -G` lookups) stays at or below today's measured budget of 15. (#333)
- `analyze` skips tshark passes whose protocols are absent from the capture: the `base` pass reads every frame once, and each subsequent pass is launched only when at least one of its protocol tokens appears in `frame.protocols` (#328). A skipped pass yields the same empty rows it would have, so reports are byte-identical; passes invoked with decode-as or TLS-key decryption arguments are never skipped.
- `pcap-doctor analyze --csv FILE` and `--case FILE`: the shown findings as an RFC 4180 CSV (columns: id, severity, confidence, category, code, detector, title, location, flow_key, frame, evidence, summary, remediation, references) and as a CASE (JSON-LD) document, alongside the existing `--sarif` and `--json-out`.
- TLS server cipher-order preference (`TLS_SERVER_CIPHER_PREFERENCE`): reports when the server's ServerHello cipher is not the first suite in the ClientHello, i.e. the server imposed its own preference order rather than the client's (#272).
- `pcap-doctor logs` now exports `netbios`: NBNS/NetBIOS name resolution (UDP/137), one row per queried
  name with the addresses the responder(s) returned, `is_group` from the NB flags group bit, and the
  originator/responder endpoints. Unresolved queries still get a row with no address.
- `pcap_doctor.slice.slice_capture`: cut a subset capture out of a classic pcap by host, frame numbers or flow, frames copied byte for byte. Library function only; no CLI command yet (#256).

- New detector `d14.hostnames` reports `INTERESTING_HOSTNAME`: hostnames with a login/admin/sign-in-style first label (e.g. `login`, `admin-panel`, `signin`, `wp-admin`) seen in cleartext DNS queries, TLS SNI and HTTP Host headers, where they disclose a sensitive panel address to an on-path observer (Zeek `Interesting_Hostname_Login` / `External_Name` parity, #239).
- tshark passes that do not read any `tcp.analysis.*` or `_ws.expert.*` field now pass `-o tcp.analyze_sequence_numbers:FALSE`, skipping tshark's expensive TCP sequence analysis on those passes and roughly halving wall time on TCP-heavy captures (#329).
- tshark passes that do not read any `tcp.analysis.*` or `_ws.expert.*` field now pass `-o tcp.analyze_sequence_numbers:FALSE`, skipping tshark's expensive TCP sequence analysis on those passes and roughly halving wall time on TCP-heavy captures. Only transport-only passes (frame/ip/tcp/udp/arp/icmp/eth fields, no application-protocol display filter) get the flag; app-protocol passes keep analysis on so retransmitted segments are not re-dissected (#329).
- `pcap_doctor.carving`: per-packet carving by magic bytes. `carve(index)` scans the raw payload bytes of every packet (TCP and UDP, not reassembled streams) for the file signatures in `filetypes.MAGIC` and returns, per frame, the matched signature (MIME) and the byte offset it occurred at; `scan_payload(payload)` runs the same scan on any byte blob. Library function only — no CLI wiring, no new findings (#219).
- `pcap-doctor carve CAPTURE`: lists the magic-byte hits of `pcap_doctor.carving` per frame (signature, payload offset, TCP or UDP) as a table, or as JSON with `--json`. `--out DIR` writes each carved payload, from its signature to the end of its packet payload, as `frame<N>-<offset>.<ext>` (0600, never opened). `--streams` carves reassembled TCP streams per direction, so a file split across segments is found whole. Creates no findings (#216).
- Host inventory enriched with MAC address, OUI vendor, observed hostname (DHCP option 12, NBNS name, TLS SNI), and OS guess from initial TTL (#245).
- Suricata-style file rules: a `file_rules` module with `FileRule` (name glob, size range, magic MIME, md5) and `file_rules_match` for matching extracted file records by any combination of those keywords (#275).
- G.711 mu-law (PCMU) and A-law (PCMA) decode tables and helpers (`pcap_doctor.g711`) for decoding RTP audio payloads (payload type 0 / 8) to 16-bit PCM WAV at 8 kHz. Decode tables are verified against ffmpeg's built-in PCMU/PCMA decoders (#214).
- Every finding code now resolves to a Suricata-style `classtype` (from `attempted-recon`, `trojan-activity`, `policy-violation`, `protocol-command-decode`, `misc-activity`, `attempted-admin`), via a single mapping table keyed by code in the rule registry; unmapped codes default to `misc-activity`. The `classtype` is a new field next to the existing ones in the JSON envelope and EVE `alert` events. No existing text, score, sort order or golden changed (#241).
- A new `d16.web_attack` detector reports SQL injection, XSS, local file inclusion, path traversal and OS command injection in HTTP request URIs (`HTTP_WEB_ATTACK_*` findings), percent-decoding the URI once before matching so that encoded payloads are still caught.
- The TLS cipher detector now reports `TLS_NO_SCT` (low) when a server's leaf certificate lacks the Certificate Transparency SignedCertificateTimestampList extension (OID 1.3.6.1.4.1.11129.2.4.2, RFC 6962 section 6.1), so certificates without embedded CT auditability are surfaced for review (#265).
- ECH (Encrypted Client Hello, extension 0xfe0d per RFC 9849) and TLS 1.3 0-RTT early-data (early_data extension 42 per RFC 8446) checks: new detector `d17.ech_early_data` reports `TLS_ECH_OFFERED` and `TLS_EARLY_DATA_OFFERED` when the ClientHello offers these extensions, since a passive tool cannot decrypt them (#270).
- `pcap-doctor analyze` now emits structured progress events (pass started/finished with elapsed time, detector started/finished, findings as they are produced). On a terminal (stderr TTY) it shows a live rich progress display with a progress bar, elapsed time, current stage, and a running severity tally; on non-TTY/CI it prints at most one plain line per stage to stderr and touches nothing on stdout, so reports and scores are byte-identical with progress on or off (#332).
- IRC password via PASS command and NickServ IDENTIFY, and SOCKS5 username/password (RFC 1929) cleartext credentials are now detected as CLEARTEXT_CREDENTIAL findings by the transport-exposure detector (#231).
- A new `rfb` Zeek-style log records the RFB/VNC handshake on TCP 5900: the server and client protocol version
  strings, the security types offered by the server and the one selected by the client, the authentication result
  (success/failure), and the desktop name from ServerInit. The `vnc` tshark pass backs it, and `pcap-doctor query
  ... -s log:rfb` reads the table.
- `stun.log` and `rtsp.log`: Zeek-style per-protocol logs for STUN (message type and the XOR-MAPPED-ADDRESS when present) and RTSP (method, URL and response status) as `pcap-doctor logs` rows or TSV/JSON (#224).
- `bittorrent` log: Zeek-style log for BitTorrent DHT messages (query type — ping, find_node,
  get_peers, announce_peer — transaction id and, for get_peers/announce_peer, the info_hash as hex)
  and peer-wire handshakes (info_hash and peer-id version prefix), parsed passively from the bt-dht
  heuristic dissector and the bittorrent handshake (#276).
- HTTP/2 over cleartext (h2c, prior-knowledge) is now reported as HTTP2_CLEARTEXT findings by a new `d5.http2` detector, recording the decoded `:method`, `:path`, `:authority` and `:status` pseudo-headers per stream (#226). TLS-encrypted HTTP/2 is unchanged (carried inside TLS, out of scope).
- A `syslog` Zeek-style log (RFC 3164 and RFC 5424 over UDP/514) is now produced by `pcap-doctor logs`, recording facility, severity, version, timestamp, hostname, app/tag, process id, message id and the message text (truncated to 200 chars) (#228).
- Cleartext POP3 USER/PASS, IMAP LOGIN and SMTP AUTH PLAIN credentials are now reported as CLEARTEXT_CREDENTIAL findings by the transport-exposure detector.
- `pcap-doctor analyze --fast`: an opt-in flag that pre-splits the capture with a libpcap BPF filter (`tcpdump -r in.pcap -w sub.pcap`) for passes whose protocols live on well-known ports (DNS on 53, NTP on 123, SSH on 22, Telnet on 23, SIP on 5060, SMB on 445, and the cleartext services pass), then runs only those passes on the small sub-capture. Default behaviour is unchanged. Falls back to the normal full-capture scan if tcpdump is missing, and prints a note that protocols on non-standard ports are not covered (#334).
- RADIUS `radius.log` (ts, uid, id.orig_h/id.orig_p/id.resp_h/id.resp_p, username, mac, result) and a `d18.radius` detector that raises CLEARTEXT_CREDENTIAL findings for Access-Request exchanges carrying a cleartext User-Name.
- DHCPv6 Solicit/Advertise/Request/Reply exchange log (`dhcpv6.log`): client DUID/MAC, client and server link-local addresses, assigned IPv6, lease time, requested/assigned addresses, hostname (Client FQDN option), vendor class, and DNS servers, grouped by transaction ID with message types — the IPv6 sibling of the existing DHCP log (#220).
- `pcap-doctor analyze --jobs N` (and `PCAP_DOCTOR_JOBS`): cap the number of concurrent tshark passes, defaulting to `max(1, min(3, cpu_count // 2))` instead of `cpu_count` (#331). tshark children now launch at low priority (POSIX `os.nice(10)` via `preexec_fn`, Windows `BELOW_NORMAL_PRIORITY_CLASS`) so the machine stays responsive during analysis.
- `pcap-doctor analyze --jobs N` (and `PCAP_DOCTOR_JOBS`): cap the number of concurrent tshark passes, defaulting to `max(1, min(3, cpu_count // 2))` instead of `cpu_count` (#331). tshark children now launch at low priority (POSIX: `nice -n 10` as a command prefix; Windows: `BELOW_NORMAL_PRIORITY_CLASS`) so the machine stays responsive during analysis.
- `pcap-doctor packets` and `pcap-doctor packet`: a per-packet explorer over the capture. `packets` lists frames (number, time, source, destination, protocol, length, info) and takes a Wireshark display filter with `-Y`; `packet CAPTURE FRAME` prints the full dissection tree and the hex view of one frame (`--json` for the nested tree, `--no-hex` to drop the dump). Read-only: tshark is asked for exactly what was requested.
- `pcap-doctor follow CAPTURE PROTO STREAM` (PROTO: tcp, udp, tls, dtls, http, http2, quic, sip): the reassembled payload of one stream, per direction, as text or hex, or written to a file with `-o` (`--direction client|server` writes one side). TLS and HTTP-over-TLS streams decrypt with `--tls-key` or `--keylog`. `pcap-doctor streams CAPTURE` lists the TCP/UDP stream numbers with their endpoints.
- `pcap-doctor query CAPTURE EXPR`: a query language for the analysed data, the zeek-cut / Brim counterpart of Wireshark's display filter (which stays on `packets -Y` for raw frames). `app_proto == "tls" and bytes > 10000`, `port_b in {80 8080}`, `endpoint_a == 10.0.0.0/8`, `host contains "example"`, `not encrypted`; operators `== != < <= > >= contains matches in`, `and`/`or`/`not` (or `&&` `||` `!`), parentheses; list fields match on any element; an unknown field is an error that lists the known ones. `--source` picks flows, hosts, tls, http, dns, sip, rtp, ssh, quic, services or findings; `flows -f EXPR` filters the flow table. The expression is parsed, never evaluated.
- `pcap-doctor logs CAPTURE`: Zeek-style per-protocol logs, `conn dns http ssl x509 files notice weird dhcp ftp smtp ssh smb`, in Zeek's TSV format (`--format tsv`) or as one JSON object per line (`json`, `both`), with Zeek's column names and types. Each table is also a `query` source (`-s log:conn`). Differences from Zeek (approximated `history`, payload-only byte counts, no secrets) are listed in [docs/zeek-logs.md](docs/zeek-logs.md). New on-demand tshark passes `conn`, `dhcp`, `ftp`, `smtp`, `smb`, `weird`; `analyze` does not run them.
- `pcap-doctor eve CAPTURE`: Suricata EVE-compatible JSON events for SIEM ingest, one object per line and time-ordered: `alert` (one per finding; `signature_id` is derived from the finding code, 9000000-9999999; `severity` 1 for critical/high, 2 medium, 3 low/info), `flow`, `dns`, `http`, `tls` (SNI, subject/issuer, JA3/JA3S) and `fileinfo`. Built from the Zeek-style log tables so both outputs agree. `--types` selects events, `-o` writes a file.
- `pcap-doctor analyze --signatures FILE` (repeatable, `--sig-var NAME=VALUE`): a signature engine for your own detections. Suricata rule subset (`*.rules`: `alert|pass|drop|log`, tcp/udp/ip, address and port lists with CIDR, negation and `$VARS`, `->`/`<>`, `msg content(|hex|, !, nocase, offset, depth, distance, within) pcre dsize flow flags sid rev classtype priority`) and Zeek signatures (`*.sig`: `ip-proto`, `src/dst-ip`, `src/dst-port`, `payload /re/`, `event`). TCP payloads are matched per direction on the reassembled-in-order stream, so a pattern split across segments still hits; each rule fires once per flow as `SIGNATURE_MATCH` (new detector `d9.user_signatures`, category Signatures). A rule using an unsupported keyword is skipped with a note in the report, never approximated.
- `pcap-doctor extract CAPTURE`: writes the files a capture carries to `CAPTURE.files/<protocol>/` plus a `manifest.json`: HTTP bodies, FTP data, SMB file transfers, TFTP and DICOM objects (tshark `--export-objects`, so chunked/compressed bodies are reassembled) and mail from SMTP `DATA`, POP3 `RETR` and IMAP `FETCH`, kept as `.eml` and split into attachments. Names are reduced to a safe basename, paths cannot leave the output directory, files are mode 0600 and nothing is ever opened or run. TLS-wrapped HTTP extracts with `--tls-key` / `--keylog`.
- File hashing and MIME typing: every file `extract` writes is hashed (MD5, SHA-1, SHA-256) and typed by magic bytes (executables, archives, documents, images, media, scripts; the file name is only a fallback) in `manifest.json`. The Zeek-style `files.log` now lists the extracted files with `seen_bytes md5 sha1 sha256 mime_type`, and the `eve` `fileinfo` events carry the same hashes, size and `magic`.
- SMB / SMB2 / SMB3 dissection: a new `smb` pass feeds `index.smb` (command, status, share, file, NTLM user/domain/workstation, dialects, signing mode), queryable with `query -s smb` and shown by `pcap-doctor smb CAPTURE` (users, shares, files). New detector `d10.smb` (category SMB): `SMB1_IN_USE`, `SMB_SIGNING_NOT_REQUIRED`, `SMB_NULL_SESSION`, `SMB_ADMIN_SHARE_ACCESS`, `SMB_REMOTE_EXEC_PIPE` (svcctl/atsvc/PSEXESVC), `SMB_EXECUTABLE_ON_SHARE`.
- New detector `d19.vpn_handshakes` (category Network): identifies IKE/IPsec ISAKMP handshakes on UDP 500/4500, WireGuard handshakes on UDP 51820 and OpenVPN control-channel traffic on UDP/TCP 1194, as informational findings (#223).
- `dns.log` now records SVCB, HTTPS, RRSIG, DNSKEY, DS, NSEC and NSEC3 answer values alongside the already-supported TXT/MX/NS/PTR/SRV/SOA/CAA (#229).

## [0.8.0] — 2026-10-09

Machine output now follows the shared **doctor/1** contract (`docs/doctor-contract.md`). This is a
breaking change to `--json`, `--json-out`, `--sarif`, `--baseline` and the exit codes; there is no
legacy flag. `report.json` on disk and its `schema_version` (1.6.0) are unchanged.

### Changed (breaking)

- **`--json` / `--json-out`** print `{schema: "doctor/1", tool, version, exit_code, score: {value, label,
  model, coverage_gaps}, findings, data}`. The old `{tool, version, score, label, categories, report}` is gone:
  the old `report` (without its findings) and `categories` are under `data`, and `new_findings` became
  `baseline_state` on each finding plus a top-level `baseline: {new, unchanged, fixed}`.
- **Findings** in the envelope use the contract keys: `id` is the rule code, `fingerprint` a 16-hex
  identity (client ephemeral port masked), `message` the title, `remedy` the remediation, `location`
  `{kind, ref}`, `evidence` `[{ref, value}]`. The old per-run id is kept as `finding_id`.
- **Exit codes:** with `--baseline`, a new finding at or above `--fail-on` exits **3** (was 1);
  `analyze` exits 130 on SIGINT.
- **Score labels** are `good` (>= 90), `needs work` (>= 60), `critical`; the formula is unchanged and named `pcap/1`.
- **`--baseline`** matches by `fingerprint` only and reads a doctor/1 envelope (a `report.json` still works).
- **SARIF:** the fingerprint key is `doctorFinding/v1` (was `pcapDoctorFindingId/v1`) and runs carry `properties.score`.
- `pcap-doctor schema` reports `doctor/1` next to the report schema version; `pcap-doctor why` also accepts a fingerprint.

### Added

- `pcap-doctor mcp`: an MCP server over stdio (11 tools: analyze, why, rules_list, rules_explain, keys_scan, flows,
  ciphers, detectors, suites, doctor, schema). `analyze` returns the doctor/1 envelope unchanged; `watch`,
  `install` and `ci install` are not exposed (README, "MCP server").
- `docs/doctor-contract.md` and a conformance test (`tests/test_doctor_contract.py`), including an escape-sequence
  test through the human renderers.

## [0.7.0] — 2026-10-05

Every change in this release was found by stress-testing the tool against real firmware images and
real captures rather than against its own fixtures. Two rounds of that work turned up defects in
`keys scan` and in the TLS certificate path; a third found a way for attacker-chosen capture text to
reach a report with raw terminal escapes still in it.

Report schema **1.5.0 → 1.6.0**.

### Fixed

- **A DSA key was judged by the RSA threshold and described as RSA.** `weak_key_verdict` had an
  elliptic-curve branch and then an RSA rule that everything else fell into, so a 1024-bit DSA key was
  reported as `"RSA keys below 2048 bits are outside current guidance"`. A DSA prime size is not
  comparable with an RSA modulus, so it is now reported as undecided with a reason rather than
  borrowed (#155, #152).
- **Elliptic-curve keys were flagged `weak-key-256bit`.** The `bits` field holds a modulus size for
  RSA and a curve size for EC, and one threshold was applied to both -- so a NIST-recommended P-256 key
  read as breakable. Strength is now decided per algorithm (#144, #153).
- **A certificate's key size was never read,** so a shipped 768-bit RSA certificate produced no
  weakness flag at all. Certificates now report their algorithm and their RSA modulus size (#143, #146,
  #149, #159).
- **`TLS_LEGACY_RECORD_VERSION` fired 26 times across the corpus and every one was the ClientHello
  sentinel** that RFC 8446 and RFC 5246 require and tell readers to ignore. The record layer now
  keeps a frame and a content type per record, so the post-handshake case -- a peer that really would
  downgrade -- is distinguished from the sentinel instead of being reported as inventory (#157, #164,
  #150, #158).
- **An attacker-chosen HTTP `Host` header reached `03-findings.md` with raw ANSI escapes intact,**
  including a screen clear followed by red text reading "no findings" -- in the file the README tells
  people to paste into a ticket. `keys scan`'s table had the same problem with a firmware file name,
  which rich would additionally have displayed as a path the analyst does not have (#167, #170, #172,
  #169, #173, #174, #176).
- **`keys scan --json` returned the raw escape,** because `json.dumps` encodes it as a six-character
  sequence. It is a machine surface, so the value is now filtered at the envelope (#175, #177).
- **The `watch` signal test raced the process reaper,** failing intermittently under load (#179).
- `keys scan` applies the published curve policy (#162, #165), and an unreadable certificate is now a
  row that says why instead of vanishing (#163).

### Changed

- Capture-chosen text is filtered once, where a finding is built, and again only where a surface
  needs something different: a terminal additionally escapes markup, a JSON surface deliberately does
  not. The rule is written down in AGENTS.md so the asymmetry is not "harmonised" into a bug (#171,
  #172).

### Added

- A real-world stress corpus: 141 OpenWrt firmware images across seven releases, 219 captures from the
  wireshark test suite, and 49 key-material vectors, each with the properties it must be expected to
  report (#141, #142, #145, #147).
- Harnesses that cross-check the tool against tshark, check its report contract, plant adversarial
  capture text, and **prove they would still notice if the tool regressed** (#154, #160, #168, #178,
  #180, #181, #182, #183, #184).

### Known limits, unchanged

- No fixture covers a genuine downgraded TLS application record; the positive path is covered by unit
  tests over a constructed session (#166).
- There is deliberately no DSA threshold (#155) and no minimum-curve policy in `keys scan` beyond the
  published floor (#151).


## [0.6.0] — 2026-10-03

Closes the caveats left after 0.5.0: re-captures match their baseline, live `watch` is proven and stops
cleanly, firmware downloads are recognised from the response headers, and indexing is about twice as fast.

### Fixed

- `watch` prints a finding once, not again for every new client connection to the same service: it dedupes
  on the same port-insensitive match as `--baseline` (#136).
- `--baseline` no longer reports every finding as new when the same device is captured again: a finding is
  known when only its client's ephemeral port changed (detector, code, title and flow key are compared with
  the higher port of each flow masked). Finding ids are unchanged (#126).

### Changed

- CI copies through `wl-copy` under a real headless Wayland compositor (sway) and reads it back with
  `wl-paste`, so the Wayland clipboard path is proven like X11, macOS and Windows already were (#129).
- A plain-HTTP firmware download is also recognised from the response: a `Content-Disposition` file name with a
  firmware extension, or a firmware-only content type (`application/x-firmware`,
  `application/vnd.android.ota-package`, `application/x-ota-package`); the evidence names the header that fired.
  `application/octet-stream` alone is not a signal. Existing findings are unchanged (#130).
- `watch` prints the exact command that grants live-capture rights on this OS (macOS ChmodBPF / `access_bpf`,
  Linux `wireshark` group or `setcap` on dumpcap, Windows Npcap) when capturing fails. CI now runs a real
  `watch -i lo` capture on Linux and checks a finding comes out and no capture process is left. `watch` now
  also stops cleanly on SIGTERM and when started in the background (`watch &` ignores Ctrl-C's SIGINT);
  before, both left dumpcap running (#128).
- Indexing runs the independent tshark passes concurrently (RTP still waits for SIP). Reports are identical;
  on a 120 MB / 509k-packet capture `analyze` took 41 s instead of 91 s, at about +0.8 GB peak memory (#127).

## [0.5.0] — 2026-09-30

White-box firmware testing: decrypt a capture with key material you supply, inventory the keys an
image ships, and flag a server key that ships in the firmware. Plus cross-platform CI.

### Added

- **Decrypt your own capture with key material you supply** (authorized white-box testing). `analyze` gains
  `--tls-key FILE` (repeatable), `--tls-key-password`, `--keys-from DIR` (every PEM private key under an
  extracted-firmware tree), `--keylog FILE` and `--psk HEX`. An RSA private key decrypts RSA-key-exchange
  sessions (no forward secrecy) that match the server certificate; decrypted inner HTTP then flows through the
  existing detectors, and a `[decrypt] read inner traffic from N of M TLS session(s)` note is added. Key
  material is passed straight to tshark and never written to any artifact (#115).
- `pcap-doctor keys scan DIR` inventories the key material in an already-extracted firmware tree: every PEM
  private key and certificate, flagged for weak keys (<=1024-bit RSA), self-signed, expired, and — the
  dangerous one — a private key whose public half matches a shipped certificate (you hold the key for that
  cert). `--json` for the machine form; `--out KEYS_DIR` normalises the private keys for
  `analyze --keys-from`. Private-key bytes are never printed (#117).
- Each certificate now carries a public-key fingerprint `spki_sha256` (the non-secret
  `sha256(DER public key)[:16]`), so a key seen on the wire can be matched against a private
  key found in firmware. Report schema bumped to **1.5.0** (#119).
- `analyze --firmware DIR` (repeatable) correlates the capture against an extracted-firmware tree:
  when a session's server certificate has the same public key as a private key in the image,
  pcap-doctor reports **`TLS_KEY_IN_FIRMWARE`** (critical) — the key that protects this channel
  ships in every device, so anyone with the image can passively decrypt and tamper with it. Keys
  supplied via `--tls-key`/`--keys-from` are correlated too. Only the non-secret SPKI fingerprint
  and the firmware path appear in the report (#121).

- CI proves pcap-doctor on **Linux, macOS and Windows**:
  - tshark from each OS's package manager;
  - the same finding codes on every fixture (`tests/fixtures/expected_codes.json`);
  - every command run with piped output;
  - a real clipboard round trip;
  - the full test suite on macOS (#108).
- The npm package has a README, and the PyPI page links the repository, issues and changelog. README
  images and links are absolute, so they work on PyPI and npm (#105).

### Changed

- The tshark cache is set with `PCAP_DOCTOR_CACHE` and defaults to `~/.cache/pcap-doctor`; the older
  `PCAP_FORENSICS_CACHE` is still honoured (#112).

### Fixed

- Copy on Windows goes through PowerShell's `Set-Clipboard`. `clip.exe` put an invisible byte-order
  mark (U+FEFF) at the start of the copied text; a real Windows runner caught it (#108).
- `pcap-doctor.toml` or `[tool.pcap-doctor]` is found from subfolders, up to the repository root. Before,
  a run from `captures/` silently ignored the repository's config (#106).

- The interactive text screens scroll. Show findings report, Show fix prompt, the workflow and the
  launch preview used to show only their first lines and looked stuck. Keys: ↑/↓, PgUp/PgDn, Space,
  g/Home and G/End. Lines wrap to the terminal, so the key footer always stays visible (#104).

## [0.4.0] — 2026-09-30

Findings reports for security testers, and copying that works on every machine.

### Added

- *Choose how to continue* copies or shows a **findings report**: a security-weakness report in
  Markdown for one finding or all of them. Review's enter copies it for the selected finding, and
  **s** saves it (#101).

### Fixed

- Copy works everywhere. It picks the clipboard tool that fits the session (`pbcopy`, `wl-copy`,
  `xclip`, `xsel`, `clip.exe`, `termux-clipboard-set`) and says "copied" only on success. Otherwise it
  uses OSC 52 and also saves the text next to the report. A stock Ubuntu, with no clipboard tool,
  previously just failed (#101).

## [0.3.0] — 2026-09-30

Interactive results in the terminal, for security testers and developers.

### Added

- Interactive results after a scan in a terminal, modelled on React Doctor. A spinner shows each stage,
  then the score header with the potential score after priority fixes, then an arrow-key menu:
  - **Review**: findings grouped by category, with impact, evidence, fix and rule guide; enter copies
    ticket-ready text.
  - **Add to GitHub Actions**.
  - **Hand off to an agent**, with the prompt always previewed.

  Piped output, files, CI, `--json`, `-q` and `--score` are unchanged (#98).

### Fixed

- The npm launcher's tests run on Node 20 and 22; `node --test test/` failed on Node 22, which the
  release job uses (#96).

## [0.2.0] — 2026-09-30

**pcap-forensics is now pcap-doctor**: one command gives a health score, findings grouped by category,
explanations, a CI gate on new findings, and a handoff to AI coding agents. `pf` stays as an alias.
`report.json` keeps `schema_version` `1.4.0`: everything new is computed around the report.

### Added — pcap-doctor

- Distribution and command `pcap-doctor`, `--version`; `npx pcap-doctor` launcher (runs the same
  version through `uvx` or `pipx`); PyPI and npm releases by trusted publishing,
  with no stored token (#46, #50, #51, #93).
- The CLI is a package of self-registering command modules (#45).
- A rule catalog with eight categories, `rules list` / `rules explain`, and a doc per finding code
  (#47, #49, #61).
- A local 0-100 health score and a summary grouped by category; `--score`, `--verbose` (#48, #53).
- `--category`, strict option validation (unknown values exit 2 before tshark runs) (#52).
- `--json` / `--json-out` envelope, `--sarif` (SARIF 2.1.0), `--baseline` to show and gate only new
  findings (#54, #55, #56).
- `pcap-doctor.toml` / `[tool.pcap-doctor]`: `disable`, `[severity]`, `[[allow]]` with a reason,
  `categories`, `fail_on`, and the `ota` profile (`--config`, `--profile`); every suppression is
  noted in the report (#57, #58).
- `why <frame|id>` with `--prompt`; an AI handoff menu after interactive scans (Claude Code, Codex,
  Cursor; `--safe`, `--no-handoff`), agent guidance inside agent shells, and a fenced
  untrusted-data prompt builder (#49, #59, #60).
- `install` writes agent guides (Claude Code skill, Cursor rule, AGENTS.md block) (#62).
- `ci install` and a composite GitHub Action that compares each capture with its base-branch copy,
  comments once on the PR and uploads SARIF (#63).
- `watch -i IFACE`: ring-buffer live capture that prints each finding the first time it appears (#64).
- `HTTP_CLEARTEXT`: plain HTTP is reported per flow, high when a request path looks like a firmware or
  package download (so `--profile ota` fails it) and medium otherwise; query strings are never written
  to a report (#91). A new fixture, `http_cleartext.pcap`, covers it.

### Changed — pcap-doctor

- The npm launcher is published with npm trusted publishing (OIDC) instead of an `NPM_TOKEN` secret;
  the release job skips with a notice when the package is not on npm yet (its first publish is
  manual) or the version is already published (#93).

### Fixed — pcap-doctor

- RFC citations in TLS version and cipher-policy text (#72).
- The tool version in reports now comes from the installed package instead of a hard-coded string (#65).

**MVP hardening since 0.1.0 (issues #1–#44):**

`report.json` `schema_version` is `1.4.0` (additive: `Flow.first_frame`, `Flow` burst statistics,
`RtpStream.first_frame`, `SshSession.offered_in`, `TelnetLogin`).

### Added

- Telnet logins: passwords typed after a `Password:` prompt are reported as `CLEARTEXT_CREDENTIAL`
  (length and frame only, never the text); Telnet sessions now raise `CLEARTEXT_SERVICE` (#37).
- `SSH_TERRAPIN_EXPOSED`: chacha20-poly1305, or an EtM MAC with a CBC cipher, offered without strict
  key exchange on both sides (#24).
- FTP `PASS` arguments and LDAP simple-bind passwords are reported as `CLEARTEXT_CREDENTIAL` (#14).

### Fixed — secrets

- SNMP community strings and MySQL queries are redacted where the index builds service details (#1).
- A scheme-less `Authorization` value (bare token) no longer appears in a finding title or evidence (#15).

### Fixed — evidence and correctness

- Every finding cites a real frame: RTP, SYN scan, odd-port, beaconing and DNS resolver evidence no
  longer cite frame 0 or a stream index (#4, #6); SSH evidence cites the KEXINIT, not the banner (#25).
- The server's SSH KEXINIT no longer overwrites the client's offer (#25).
- `BEACONING_SHAPE` measures regularity of gaps between bursts; the old check could never fail (#10).
- `SERVICE_ON_ODD_PORT` no longer reports a client's ephemeral port (#16).
- `DNS_EXTERNAL_RESOLVER` finds the resolver by port and covers IPv6 and all private ranges (#6);
  `DNS_TUNNEL_SHAPE` names the querying host and no longer counts responses as queries (#18).
- `chacha20-poly1305@openssh.com` is no longer listed as a weak SSH cipher (#2).
- Invalid or wrong finding references replaced (e.g. `CWE- exfil`, RFC 8999 on TLS findings) (#3).
- The service field list is shared with the tshark pass; four names that are not tshark fields were removed (#14).
- `WELL_KNOWN_PORTS`: 506/522/1194 mapped to the wrong service (#23).

### Changed — docs

- README redesigned CLI-first: light/dark logo, badges, a numbered get-started path including a CI
  gate, a table of contents, exit codes, and a privacy/telemetry section; the documented default
  output folder is corrected to `<capture>.pf-report/` (#41).
- CONTRIBUTING gains how-to-start, pull-request and other-ways-to-help sections; a pull request
  template follows the AGENTS.md contract (#41).

### Fixed — project

- Mermaid: `04-diagrams.md` emitted an invalid RTP gantt for captures without RTP (28 of 179 generated
  diagrams failed to render), and the README's sequence diagram broke on a `;` (#43).
- CI could never pass (non-existent tshark preference, fixture drift check on randomly captured TLS
  fixtures); it now runs the full suite (#12).

## [0.1.0] — 2026-09-29

First working release. `report.json` `schema_version` is `1.0.0`.

### Added — parsing

- `TsharkRunner`: 10 pinned tshark passes, `-T fields` with a documented
  separator/aggregator, content-addressed disk cache keyed by capture SHA-256,
  tshark version and pass arguments.
- Field and display-filter drift handling: fields validated against
  `tshark -G fields`, protocol tokens against `tshark -G protocols`, preferences
  against `tshark -G defaultprefs`; every drop recorded as a report note.
- `CaptureIndex`: flows, hosts, TLS/DTLS sessions, HTTP exchanges, DNS queries,
  SIP messages with SDP, RTP streams, SSH sessions, QUIC sessions, and other
  recognised services.
- SDP-driven RTP decode-as, so media on dynamic ports is dissected at all.
- Certificate enrichment through `openssl x509`, with an explicit
  `name_source` field and a tshark-flattened fallback.
- Cipher registry of 424 suites derived from tshark's own value table, with
  weakness tags and forward-secrecy reasoning derived from the IANA name.

### Added — detectors

- `d1.tls_cipher`: deprecated versions, weak/prohibited suites, offered-but-unused
  weak suites, missing forward secrecy, certificate expiry/key size/signature,
  self-signed leaf, alerts, truncated handshakes, JA3 fleet clustering.
- `d2.transport_exposure`: cleartext HTTP auth, Basic auth inside TLS, cookies
  without `Secure`, cleartext services, leaked credentials, services on odd
  ports, unanswered-SYN scan shape, beaconing shape.
- `d3.sip_rtp`: SIP call graph, cleartext signalling with auth headers, SDP
  without `a=crypto`, unprotected RTP, media volume anomalies.
- `d4.dns_quic_ssh`: plaintext DNS leakage, DNS tunnelling heuristics, external
  resolvers, QUIC version inventory and payload opacity, weak SSH negotiation.

### Added — output

- Six artifacts per run: `index.md`, `01-flows.md`, `02-ciphers.md`,
  `03-findings.md`, `04-diagrams.md`, `report.json`.
- Mermaid topology, crypto matrix, severity pie, per-detector bar chart, RTP
  timeline and SIP sequence diagrams, all total functions.
- Stable finding ids (`detector.code.sha256(scope)[:16]`) so reports diff.
- `pf` CLI: `analyze`, `flows`, `ciphers`, `detectors`, `suites`, `doctor`,
  `schema`, with `--fail-on` for CI gates.

### Added — safety

- Credential redaction at the model boundary, with tests that grep the artifacts
  for the original material.
- One detector raising an exception cannot sink a run; it is reported as a note.
- Unknown cipher ids, unparseable certificates and missing tshark fields all
  produce findings or notes, never silent passes.

### Added — engineering

- 85 tests across four layers: registry, tshark boundary, detectors with
  synthetic fixtures, and regression assertions over the Wireshark sample
  corpus checked by hand against `tshark -V`.
- Fixtures generated deterministically; TLS fixtures captured from genuine
  OpenSSL handshakes through a logging proxy.
- `ruff`, `mypy --strict` and `pytest` are the CI gate (`make verify`).
- `AGENTS.md` and `docs/subagent-playbook.md`: the subagent isolation contract
  and a 54-item seed issue board (`docs/issue-board.md`).

### Known limits

- Encrypted payloads (QUIC, TLS 1.3 application data) are opaque without a keylog.
- Certificate subject/issuer require openssl; without it the report says so.
- DNS tunnelling and beaconing are heuristics, reported at low confidence.
- Server/client orientation uses port heuristics; odd ports are flagged instead
  of trusted.
