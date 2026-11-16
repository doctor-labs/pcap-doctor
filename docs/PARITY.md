# Benchmark: pcap-doctor vs reference network-analysis tools (#195)

This document records an evidence-based comparison of `pcap-doctor` against reference tools on the same captures available in this environment, the gaps found, and what was closed in this change. It is intentionally honest: where a tool or corpus was not runnable here, that is stated instead of inferred.

## Environment and tools actually run

| Tool | Version / status | How run | Notes |
|---|---|---|---|
| `pcap-doctor` | 0.8.0 (this worktree, `agent/195-bench`) | `.venv/bin/pcap-doctor analyze <fixture> --json` on repo fixtures | Deterministic, tshark-backed analysis. |
| `tshark` | 4.6.6 (Wireshark, Git commit 3a22c3ef473d) | system install on this macOS host | pcap-doctor's dissector backend. |
| `suricata` | 8.0.5 RELEASE (LibHTP 8.0.5, JA3/JA4 enabled, rules loaded from `/opt/homebrew/var/lib/suricata/rules/suricata.rules`) | `suricata -r <capture> -l <tmpdir> -k none` against repo fixtures | Signature/IDS view; alerts read from `fast.log`/`eve.json`. |
| `zeek` | **not runnable locally** | `zeek -r ...` attempted | Fails immediately with a broken Homebrew runtime dependency: `dyld: Library not loaded: /opt/homebrew/opt/simdjson/lib/libsimdjson.33.dylib` (referenced from node@24/libnode). No Zeek logs could be produced on this host. |
| `java` | OpenJDK 24.0.2 (24.0.2+12-54) | `java -version` | Present locally; not sufficient to run NetworkMiner headless (see below). |
| NetworkMiner | **not compared (cannot run headless)** | n/a | NetworkMiner is a .NET desktop application; it does not run headless in this environment. Its rule/fingerprint files are the intended reference, but no live comparison was executed here. |
| Instabbox sandbox `clean-1` tools (`/data/workspace/doctor-labs/tools/`: `avbtool.py`, `magiskboot`, `payload_dumper/`, `binwalk`, `unblob`, `pysim`, `simtester`, and system `suricata`/`java`; `zeek`/`avbroot` possibly building) and corpus (`/data/workspace/doctor-labs/.audit/samples/`: Jio STB OTA zip; JCOW414/JCOW411/JCOW404/JCOW401/JCO110 gateway images) | **not accessed from this environment** | SSH to `clean-1` attempted (`ssh -o BatchMode=yes -o ConnectTimeout=5 clean-1 ...`) | Host `clean-1` could not be resolved from this machine (`nodename nor servname provided, or not known`) and `/data/workspace/...` is not present locally. **`/data/workspace/doctor-labs/tools/AVAILABLE.md` could not be read and is therefore not quoted here**; tool availability/build status on the sandbox is unverified from this session. |

> Honesty note: the task requested quoting `AVAILABLE.md` from the sandbox rather than claiming a tool that could not be run. Because the sandbox was unreachable from this execution environment, the file could not be quoted; this is recorded explicitly above.

## Captures compared

Comparison used deterministic repo fixtures under `tests/fixtures/` (same bytes for every run). The sandbox audit corpus (`.audit/samples/`) was not accessible here and is not part of the executed comparison.

Representative fixtures exercised with Suricata and pcap-doctor: `heartbleed.pcap`, `web_attack.pcap`, `smb_attack.pcap`, `dns_tunnel.pcap` (plus spot checks against other fixtures via existing expected-codes tests).

## Evidence: what reference tools saw vs pcap-doctor

### Heartbleed probe (`tests/fixtures/heartbleed.pcap`)

- **Suricata 8.0.5 (ET rules, `-k none`)**: 2 alerts —
  - `[1:2018372:5] ET RETIRED Malformed HeartBeat Request` (Potentially Bad Traffic, sev 2, CVE-2014-0160)
  - `[1:2018389:4] ET EXPLOIT Possible TLS HeartBleed Unencrypted Request Method 3 (Inbound to Common SSL Port)` (Potentially Bad Traffic, sev 2, CVE-2014-0160)
- **pcap-doctor**: `TLS_HEARTBLEED_PROBE` (high, Crypto, trojan-activity) on `tcp:10.9.0.20:443<->10.9.0.66:49300` with frame evidence `tls.heartbeat_message.payload_length = 16384`, plus `TLS_LEGACY_RECORD_VERSION` (medium). Score 86/100.
- **Assessment**: parity on the core detection (both flag the CVE-2014-0160 probe). Suricata emits two signature-specific alerts with CVE metadata; pcap-doctor emits one behavioral finding with remediation and frame-level evidence.

### Web attack payloads in HTTP URIs (`tests/fixtures/web_attack.pcap`)

- **Suricata 8.0.5**: no alerts in `fast.log` (0 alerts) with the installed ruleset on this capture.
- **pcap-doctor**: flags `HTTP_WEB_ATTACK_SQLI`, `HTTP_WEB_ATTACK_XSS`, `HTTP_WEB_ATTACK_LFI`, `HTTP_WEB_ATTACK_TRAVERSAL`, `HTTP_WEB_ATTACK_COMMAND_INJECTION` (plus `HTTP_CLEARTEXT`, `HTTP_MISSING_SECURITY_HEADERS`) with per-request evidence.
- **Assessment**: pcap-doctor's URI-pattern detectors surface attack classes this Suricata ruleset did not alert on for this fixture. Suricata coverage here is ruleset-dependent; absence of an alert is not proof of absence, but it is an observed gap for this configuration.

### SMB attack behaviors (`tests/fixtures/smb_attack.pcap`)

- **Suricata 8.0.5**: 4 alerts —
  - `[1:2067085:1] ET INFO NTLM Session Setup Request - Negotiate` (Misc activity)
  - `[1:2067087:1] ET INFO NTLM Session Setup Request - Auth` (Misc activity)
  - `[1:2025701:2] ET INFO SMB2 NT Create AndX Request For an Executable File` (Potentially Bad Traffic)
  - `[1:2010781:4] ET INFO PsExec service created` (A suspicious filename was detected)
- **pcap-doctor**: `SMB1_IN_USE`, `SMB_EXECUTABLE_ON_SHARE`, `SMB_REMOTE_EXEC_PIPE` (x2), `SMB_ADMIN_SHARE_ACCESS`, `SMB_NULL_SESSION`, `SMB_SIGNING_NOT_REQUIRED`.
- **Assessment**: complementary coverage. Suricata's signatures name PsExec/executable-create/NTLM exchange events; pcap-doctor emphasizes protocol posture and abuse primitives (SMBv1, null session, admin share, unsigned, remote-exec pipe). Different lenses, overlapping risk story.

### DNS tunnelling shape (`tests/fixtures/dns_tunnel.pcap`)

- **Suricata 8.0.5**: alerts observed were checksum/protocol-decode noise on this fixture (`SURICATA IPv4 invalid checksum`, `SURICATA TCPv4 invalid checksum`; `-k none` run) and **no DNS-tunnelling/exfiltration signature alert**.
- **pcap-doctor**: `DNS_TUNNEL_SHAPE` plus `DNS_CLEARTEXT` findings (heuristic, confidence reflects shape strength).
- **Assessment**: pcap-doctor provides a behavioral tunnelling heuristic where the installed Suricata rules produced no tunnelling-specific alert on this sample. (Heuristics are leads, not verdicts — consistent with pcap-doctor's limits.)

### Zeek (not run)

Zeek could not be executed locally due to the broken `libsimdjson.33.dylib` dependency (`zeek --version` / `zeek -r` both fail at dynamic load). The sandbox `zeek` build status is unknown here because `AVAILABLE.md` was inaccessible. pcap-doctor already emits Zeek-style logs (`pcap-doctor logs`, see `docs/zeek-logs.md`) covering conn/dns/http/ssl/ssh/smb/kerberos/ntlm/files/weird/notice and many protocol-specific tables; a live Zeek-vs-logs field diff was not performed in this environment.

### NetworkMiner

Not compared (desktop .NET application, no headless run). NetworkMiner's strengths (host/file/credential carving and parameter extraction) overlap conceptually with pcap-doctor's `extract`, `carve`, host inventory and credential detectors, but no side-by-side evidence was produced.

## Coverage: what pcap-doctor provides (relevant to Zeek/Suricata/NetworkMiner)

This is a summary of areas where pcap-doctor already has first-class coverage (see `README.md` detectors table and `pcap-doctor rules list` for the authoritative catalog):

| Area | pcap-doctor coverage |
|---|---|
| TLS/crypto posture | Deprecated/weak suites & versions, no PFS, weak certs/keys/sigalgs, expiry/self-signed/mismatch/not-yet-valid, no EMS/SCT/OCSP staple, weak DH, compression, insecure renegotiation, alerts/truncation, JA3/JA4 fleet, Heartbleed probe, SNI/cert mismatch, server cipher preference. |
| Cleartext & credentials | HTTP cleartext/auth/basic/cookies, FTP/Telnet/SNMP/LDAP/mail/MySQL/MSSQL-login-related cleartext services and credential findings, redacted handling. |
| DNS | Cleartext leakage, tunnelling-shape heuristic, external resolvers, interesting hostnames; Zeek-style dns log fields. |
| SSH/QUIC | Weak kex/cipher/MAC/hostkey, Terrapin exposure, HASSH, QUIC inventory/opacity. |
| Web/app attacks | SQLi/XSS/LFI/path traversal/command injection in URIs, missing HTTP security headers, h2c. |
| SMB/Windows auth | SMBv1, signing not required, null session, admin shares, remote-exec pipes, executables on shares, Kerberos/NTLM weaknesses (etypes, no-preauth, NTLMv1, signing). |
| Network behaviors | SYN/connect scans (vertical/horizontal), beaconing, brute-force shapes, ARP spoof/ICMP redirect, capture loss. |
| ICS/VoIP/VPN/RADIUS/IoC | ICS control commands, SIP/RTP/SRTP posture, VPN handshakes, RADIUS cleartext username, user signatures and IoC matching, software-version vuln hints. |
| Artifacts & logs | File extraction/carving, Zeek-style logs, Suricata-EVE-compatible output, stream follow/packet views. |

## Gaps identified and action taken

| Gap (evidence) | Compared tool signal | Action in this change |
|---|---|---|
| DNS zone transfer requests (AXFR/IXFR) over cleartext were only surfaced as generic cleartext DNS, not as an explicit zone-transfer exposure. Zeek records `qtype=AXFR/IXFR` in dns logs and zone transfers are a standard recon/data-exposure event in IDS/NSM workflows; Suricata rule sets commonly alert on AXFR. | Protocol visibility / recon significance (Zeek dns qtype, common Suricata AXFR rules). Live Zeek run not possible here (broken local install); sandbox Zeek/AVAILABLE.md not accessible. | **Closed:** added `d25.dns_zone_transfer` emitting `DNS_ZONE_TRANSFER_REQUEST` (one finding per source/destination/zone/qtype) with frame evidence, rule doc, fixture, tests, README row, rules/classtype/catalog/expected-codes updates. |
| Zeek runtime comparison on this host | Zeek process fails to start (libsimdjson.33.dylib missing). | **Not closed:** environment issue; reported honestly. Re-run on a host with working Zeek (or on sandbox once `AVAILABLE.md` confirms availability) for log-level parity diffs. |
| NetworkMiner comparison | Desktop-only tool. | **Not closed:** not headless-runnable; reported honestly. |
| Sandbox corpus/tools (`.audit/samples/`, `/data/workspace/doctor-labs/tools/AVAILABLE.md`) | Requested reference environment. | **Not closed:** sandbox unreachable from this environment; no fabricated results. |

No detectors were added for issues already implemented or in flight per task scope (#205, #220, #224, #228, #231, #232, #253, #277).

## Notes on interpretation

- Suricata results depend on the loaded ruleset and engine settings (`-k none` used here); "no alert" means no alert from this configuration on that capture.
- Zeek and NetworkMiner comparisons were limited by environment/tooling constraints as documented above; this file favors honest "not compared" over invented coverage claims.
- Behavioral findings (e.g. tunnelling, scans, beaconing) are heuristics by design and carry confidence accordingly.