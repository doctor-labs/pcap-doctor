"""Thin, deterministic wrapper around the ``tshark`` binary.

Why subprocess ``tshark -T fields`` and not pyshark:

* field names stay visible and version-pinned (``docs/tshark-fields.md``),
* py3.13+ support is not a coin flip,
* one process per pass is far faster than per-packet IPC,
* output is text we can snapshot in tests.

Every pass result is cached on disk keyed by (pcap sha256, tshark version,
pass name) so re-runs and test loops are cheap.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

TAB = "\t"
AGG = "\x1f"  # unit separator: safe inside field values, never in tshark output
MULTI = "\x1e"  # record separator, used by -z statistics passes

Row = dict[str, list[str]]

#: Environment variable for overriding the tshark worker pool size.
JOBS_ENV_VAR = "PCAP_DOCTOR_JOBS"


class TsharkMissingError(RuntimeError):
    pass


class TsharkRunError(RuntimeError):
    pass


def worker_count(jobs: int | None, env: dict[str, str] | None = None) -> int:
    """Pick how many tshark passes may run at once (issue #331).

    Precedence: explicit ``jobs`` (from --jobs) > ``PCAP_DOCTOR_JOBS`` env var >
    CPU-based default of ``max(1, min(3, cpu_count // 2))``.

    ``int < 1`` is rejected so a misconfigured env var can never silently
    serialise the run or spawn a zero-worker pool.

    ``env`` is optional for testability; it defaults to ``os.environ``.
    """
    environ = env if env is not None else os.environ
    raw = jobs
    if raw is None:
        env_jobs = environ.get(JOBS_ENV_VAR)
        if env_jobs:
            try:
                raw = int(env_jobs)
            except ValueError:
                raise ValueError(
                    f"{JOBS_ENV_VAR} must be an integer, got {env_jobs!r}"
                ) from None
    if raw is not None:
        if raw < 1:
            raise ValueError(f"--jobs must be >= 1, got {raw}")
        return raw
    cpus = os.cpu_count() or 4
    return max(1, min(3, cpus // 2))


def _low_priority_prefix() -> list[str]:
    """Prefix the tshark argv with ``nice`` on POSIX so children run at low priority (issue #331).

    ``preexec_fn`` is unsafe here because ``prefetch`` calls ``subprocess.run`` from a
    ``ThreadPoolExecutor`` and Python docs warn that ``preexec_fn`` can deadlock the child
    when the parent has threads.  Prefixing the command with the ``nice`` binary avoids
    forking Python code in the child: if ``shutil.which("nice")`` is missing we return
    an empty prefix and the process runs at the parent's priority (graceful degradation).
    """
    if sys.platform == "win32":
        return []
    if shutil.which("nice") is not None:
        return ["nice", "-n", "10"]
    return []


def _low_priority_kwargs() -> dict[str, Any]:
    """Extra kwargs for ``subprocess.run`` to lower child priority on Windows (issue #331).

    POSIX uses the ``nice`` prefix (``_low_priority_prefix``) instead; this returns an
    empty dict on POSIX.  Windows uses ``creationflags=BELOW_NORMAL_PRIORITY_CLASS``.
    """
    if sys.platform == "win32":
        return {"creationflags": subprocess.BELOW_NORMAL_PRIORITY_CLASS}
    return {}


@dataclass(frozen=True)
class PassSpec:
    """One tshark invocation profile."""

    name: str
    fields: tuple[str, ...]
    display_filter: str | None = None
    columns: str | None = None  # for -z passes
    #: Protocol tokens from ``frame.protocols`` that justify running this pass.
    #: When none of them appear in the capture, the pass is skipped (returns empty
    #: rows) instead of re-dissecting the whole file (#328). ``None`` means
    #: always run (e.g. ``base``).
    skip_protocols: tuple[str, ...] | None = None


#: Every protocol pass needs addresses; IPv4 and IPv6 both, because a capture
#: with only one family otherwise silently yields zero flows.
ADDR_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
)


def with_addr(fields: tuple[str, ...]) -> tuple[str, ...]:
    rest = tuple(f for f in fields if f not in ADDR_FIELDS)
    return ADDR_FIELDS + rest


#: Protocol tokens that should never gate a skip decision: transport layers
#: (always present with IP traffic) and pseudo-protocols/keywords that are not
#: application dissectors.
_SKIP_EXCLUDED: frozenset[str] = frozenset(
    {
        "tcp",
        "udp",
        "ip",
        "ipv6",
        "eth",
        "ethertype",
        "data",
        "arp",
        "icmp",
        "ip-udp",
        "frame",
        "_ws",
    }
)


def protocols_in_filter(display_filter: str) -> tuple[str, ...]:
    """Bare protocol names referenced by a display filter, stripped of fields/ops and transport-only layers.

    ``"sip || sdp"`` -> ``("sdp", "sip")``; ``"telnet && tcp.len > 0"`` -> ``("telnet",)``
    (``tcp`` is a transport layer present in every IP capture, so it is dropped).
    ``"frame"`` and ``"_ws"`` are not application dissectors, so they are dropped too.
    """
    tokens: set[str] = set()
    for clause in display_filter.replace("&&", "||").split("||"):
        token = clause.strip()
        if not token:
            continue
        head = token.split(".", 1)[0]  # "tls.handshake" -> "tls"
        if not head or any(ch in head for ch in " ()=<>!"):
            continue
        if head in _SKIP_EXCLUDED:
            continue
        tokens.add(head)
    return tuple(sorted(tokens))


BASE_PASS = PassSpec(
    name="base",
    fields=(
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "ip.proto",
        "ip.ttl",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.flags.fin",
        "tcp.flags.reset",
        "tcp.flags.push",
        "tcp.analysis.ack_rtt",
        "tcp.window_size_value",
        "udp.srcport",
        "udp.dstport",
        "udp.stream",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "icmp.type",
        "icmp.code",
        "eth.src",
        "eth.src.oui_resolved",
        "eth.src_resolved",
        "_ws.col.Protocol",
    ),
)

TLS_PASS = PassSpec(
    name="tls",
    # Application-data records are matched only when they carry a pre-TLS-1.2 record version, which
    # is the downgrade a legacy peer would perform (#157). The bound is "< 0x0303" rather than
    # "!= 0x0303" on purpose: a DTLS record version is 0xfefd/0xfeff, which is numerically far above
    # 0x0303, so the loose form would pull in every DTLS data record in every capture.
    display_filter=(
        "tls.handshake || tls.alert_message || tls.heartbeat_message "
        "|| (tls.record.content_type == 23 && tls.record.version < 0x0303)"
    ),
    fields=with_addr(
        (
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "tcp.stream",
            "udp.stream",
            "tls.record.version",
            "tls.record.content_type",
            "tls.record.length",
            "tls.heartbeat_message.type",
            "tls.heartbeat_message.payload_length",
            "tls.handshake.type",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.ciphersuites",
            "tls.handshake.comp_methods",
            "tls.handshake.comp_method",
            "tls.handshake.extensions_server_name",
            "tls.handshake.extensions_alpn_str",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.extensions_supported_group",
            "tls.handshake.extensions_signature_algorithm",
            "tls.handshake.extensions_session_ticket",
            "tls.handshake.session_id_length",
            "tls.handshake.downgrade_sentinel",
            "tls.handshake.ja3",
            "tls.handshake.ja3s",
            "tls.handshake.ja4",
            "tls.handshake.p_len",
            "tls.handshake.extension.type",
            "tls.handshake.certificate",
            "tls.alert_message.level",
            "tls.alert_message.desc",
            "x509af.utcTime",
            "x509af.generalizedTime",
            "x509af.algorithmId",
            "x509ce.dNSName",
            "x509ce.modulus",
            "x509af.subjectPublicKey",
            "x509sat.uTF8String",
            "x509sat.printableString",
            "x509sat.IA5String",
            "x509sat.CountryName",
        )
    ),
)

TLS_ALERT_PASS = PassSpec(
    name="tls_alert",
    display_filter="tls.alert_message",
    fields=with_addr(
        (
            "tcp.stream",
            "tls.alert_message.level",
            "tls.alert_message.desc",
        )
    ),
)

HTTP_PASS = PassSpec(
    name="http",
    display_filter="http.request || http.response",
    fields=with_addr(
        (
            "tcp.stream",
            "tcp.srcport",
            "tcp.dstport",
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.request.version",
            "http.response.code",
            "http.user_agent",
            "http.server",
            "http.authorization",
            "http.cookie",
            "http.set_cookie",
            "http.content_type",
            "http.response.line",
        )
    ),
)

HTTP2_PASS = PassSpec(
    name="http2",
    display_filter="http2",
    fields=with_addr((
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "http2.streamid",
        "http2.type",
        "http2.headers.method",
        "http2.headers.path",
        "http2.headers.authority",
        "http2.headers.scheme",
        "http2.headers.status",
    )),
)

DNS_PASS = PassSpec(
    name="dns",
    display_filter="dns",
    fields=with_addr((
        "udp.srcport",
        "udp.dstport",
        "tcp.srcport",
        "tcp.dstport",
        "udp.stream",
        "dns.flags.response",
        "dns.id",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.resp.name",
        "dns.txt",
        "dns.count.answers",
        "dns.mx.mail_exchange",
        "dns.ns",
        "dns.ptr.domain_name",
        "dns.srv.target",
        "dns.soa.mname",
        "dns.caa.tag",
        "dns.caa.value",
        "dns.rr.udp_payload_size",
        "dns.svcb.svcpriority",
        "dns.svcb.targetname",
        "dns.rrsig.type_covered",
        "dns.rrsig.signers_name",
        "dns.dnskey.key_id",
        "dns.ds.key_id",
        "dns.nsec.next_domain_name",
        "dns.nsec3.hash_value",
    )),
)

SIP_PASS = PassSpec(
    name="sip",
    display_filter="sip || sdp",
    fields=with_addr(
        (
            "udp.srcport",
            "udp.dstport",
            "tcp.stream",
            "sip.Method",
            "sip.Status-Code",
            "sip.Status-Line",
            "sip.Call-ID",
            "sip.CSeq",
            "sip.from.user",
            "sip.to.user",
            "sip.User-Agent",
            "sip.Via",
            "sip.auth",
            "sip.auth.algorithm",
            "sdp.media",
            "sdp.media.proto",
            "sdp.media.port",
            "sdp.connection.address",
            "sdp.crypto",
            "sdp.crypto.crypto_suite",
            "sdp.crypto.key_method",
        )
    ),
)

RTP_PASS = PassSpec(
    name="rtp",
    display_filter="rtp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "frame.len",
            "udp.srcport",
            "udp.dstport",
            "rtp.ssrc",
            "rtp.p_type",
            "rtp.seq",
            "rtp.timestamp",
        )
    ),
)

SSH_PASS = PassSpec(
    name="ssh",
    display_filter="ssh",
    fields=with_addr(
        (
            "tcp.stream",
            "tcp.srcport",
            "tcp.dstport",
            "ssh.protocol",
            "ssh.message_code",
            "ssh.kex_algorithms",
            "ssh.server_host_key_algorithms",
            "ssh.encryption_algorithms_client_to_server",
            "ssh.mac_algorithms_client_to_server",
            "ssh.compression_algorithms_client_to_server",
            "ssh.kex.hassh",
            "ssh.kex.hassh_algorithms",
            "ssh.kex.hasshserver",
            "ssh.kex.hasshserver_algorithms",
        )
    ),
)

QUIC_PASS = PassSpec(
    name="quic",
    display_filter="quic",
    fields=with_addr(
        (
            "udp.srcport",
            "udp.dstport",
            "quic.version",
            "quic.supported_version",
            "quic.long.packet_type",
            "tls.handshake.extensions_server_name",
            "tls.handshake.ciphersuite",
            "tls.handshake.ciphersuites",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.extensions_alpn_str",
        )
    ),
)

#: Application fields of the services pass. The index reads exactly these (issue #14).
SERVICE_FIELDS: tuple[str, ...] = (
    "ntp.refid",
    "tftp.source_file",
    "tftp.destination_file",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "snmp.version",
    "snmp.community",
    "snmp.var-bind_str",
    "ldap.protocolOp",
    "ldap.name",
    "ldap.simple",
    "smtp.req.command",
    "smtp.req.parameter",
    "pop.request.command",
    "pop.request.parameter",
    "imap.request",
    "mysql.command",
    "mysql.query",
    "mysql.user",
    "telnet.cmd",
    "irc.request.command",
    "irc.request.command_parameter",
    "socks.username",
    "socks.password",
)

#: 220 greeting text (#235): read by the index for banner inventory, never shown as a service detail
GREETING_FIELDS: tuple[str, ...] = ("smtp.response.code", "smtp.rsp.parameter", "ftp.response.arg")

SERVICE_PASS = PassSpec(
    name="services",
    display_filter="ntp || tftp || ftp || ftp-data || telnet || snmp || ldap || smtp || imap || pop || resp || mysql || irc || socks",
    fields=with_addr(("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", *SERVICE_FIELDS, *GREETING_FIELDS)),
)

TELNET_PASS = PassSpec(
    name="telnet",
    display_filter="telnet && tcp.len > 0",
    fields=with_addr(("tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.payload")),
)

#: DTLS carries the same handshake fields under a ``dtls.`` prefix. The index
#: normalises the prefix away, so one parser serves both.
DTLS_PASS = PassSpec(
    name="dtls",
    display_filter=(
        "dtls.handshake || dtls.alert_message "
        "|| (dtls.record.content_type == 23 && dtls.record.version < 0x0303)"
    ),
    fields=with_addr(tuple("dtls." + f[4:] if f.startswith("tls.") else f for f in TLS_PASS.fields)),
)

IPV6_ADDR_PASS = PassSpec(
    name="ipv6",
    display_filter="ipv6",
    fields=("frame.number", "ipv6.src", "ipv6.dst", "ipv6.hop_limit", "ipv6.plen"),
)

#: The passes below feed the Zeek-style logs (``pcap-doctor logs``, issue #199). ``analyze`` does not run them.
CONN_PASS = PassSpec(
    name="conn",
    display_filter="tcp || udp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "frame.len",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "tcp.flags.syn",
            "tcp.flags.ack",
            "tcp.flags.fin",
            "tcp.flags.reset",
            "tcp.len",
            "udp.length",
            "ip.len",
            "ipv6.plen",
            "tcp.seq",
            "tcp.nxtseq",
            "tcp.analysis.retransmission",
            "tcp.analysis.lost_segment",
            "tcp.analysis.zero_window",
            "tcp.analysis.duplicate_ack",
            "tcp.analysis.out_of_order",
            "tcp.checksum.status",
            "udp.checksum.status",
        )
    ),
)

DHCP_PASS = PassSpec(
    name="dhcp",
    display_filter="dhcp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "udp.srcport",
            "udp.dstport",
            "dhcp.id",
            "dhcp.option.dhcp",
            "dhcp.hw.mac_addr",
            "dhcp.ip.client",
            "dhcp.ip.your",
            "dhcp.option.requested_ip_address",
            "dhcp.option.hostname",
            "dhcp.option.domain_name",
            "dhcp.option.vendor_class_id",
            "dhcp.option.dhcp_server_id",
            "dhcp.option.ip_address_lease_time",
        )
    ),
)

NBNS_PASS = PassSpec(
    name="netbios",
    display_filter="nbns",
    fields=with_addr((
        "frame.time_epoch",
        "udp.srcport",
        "udp.dstport",
        "udp.stream",
        "nbns.id",
        "nbns.flags.response",
        "nbns.name",
        "nbns.addr",
        "nbns.nb_flags.group",
    )),
)

DHCPV6_PASS = PassSpec(
    name="dhcpv6",
    display_filter="dhcpv6",
    fields=with_addr((
        "frame.time_epoch",
        "udp.srcport",
        "udp.dstport",
        "dhcpv6.msgtype",
        "dhcpv6.xid",
        "dhcpv6.duid.type",
        "dhcpv6.duid.bytes",
        "dhcpv6.duidll.link_layer_addr_ether",
        "dhcpv6.duidllt.link_layer_addr_ether",
        "dhcpv6.iaid",
        "dhcpv6.iaaddr.ip",
        "dhcpv6.iaaddr.valid_lifetime",
        "dhcpv6.dns_server",
        "dhcpv6.vendorclass.data",
        "dhcpv6.vendorclass.enterprise",
        "dhcpv6.client_domain",
        "dhcpv6.client_fqdn_flags",
        "dhcpv6.status_code",
        "dhcpv6.status_msg",
    )),
)

FTP_PASS = PassSpec(
    name="ftp",
    display_filter="ftp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
        )
    ),
)

SMTP_PASS = PassSpec(
    name="smtp",
    display_filter="smtp || imf",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "smtp.req.command",
            "smtp.req.parameter",
            "smtp.response.code",
            "smtp.rsp.parameter",
            "imf.from",
            "imf.to",
            "imf.subject",
            "imf.date",
            "imf.message_id",
        )
    ),
)

SMB_PASS = PassSpec(
    name="smb",
    display_filter="smb || smb2",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "smb2.cmd",
            "smb2.flags.response",
            "smb2.nt_status",
            "smb2.filename",
            "smb2.tree",
            "smb2.sesid",
            "smb2.tid",
            "smb2.dialect",
            "smb2.sec_mode.sign_required",
            "smb2.sec_mode.sign_enabled",
            "smb.cmd",
            "smb.dialect.name",
            "smb.sm.sig_required",
            "smb.nt_status",
            "smb.file",
            "smb.path",
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
        )
    ),
)

#: Kerberos AS/TGS exchanges for kerberos.log (#205): principals, realms, message types, errors. No key material.
KERBEROS_PASS = PassSpec(
    name="kerberos",
    display_filter="kerberos",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "kerberos.msg_type",
            "kerberos.CNameString",
            "kerberos.SNameString",
            "kerberos.realm",
            "kerberos.crealm",
            "kerberos.error_code",
            "kerberos.padata_type",
            "kerberos.etype",
        )
    ),
)

#: NTLMSSP identities for ntlm.log (#205): user, domain, workstation, server names. Never the responses.
NTLM_PASS = PassSpec(
    name="ntlm",
    display_filter="ntlmssp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "ntlmssp.messagetype",
            "ntlmssp.negotiateflags",
            "ntlmssp.blob.length",
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
            "ntlmssp.challenge.target_name",
            "ntlmssp.challenge.target_info.nb_computer_name",
            "ntlmssp.challenge.target_info.dns_computer_name",
        )
    ),
)

RADIUS_PASS = PassSpec(
    name="radius",
    display_filter="radius",
    fields=with_addr((
        "frame.time_epoch",
        "udp.srcport",
        "udp.dstport",
        "radius.code",
        "radius.id",
        "radius.User_Name",
        "radius.Calling_Station_Id",
    )),
)

TUNNEL_PASS = PassSpec(
    name="tunnel",
    display_filter="gre || vxlan || geneve || gtp || mpls || erspan || pppoes || vlan",
    fields=with_addr(
        (
            "frame.time_epoch",
            "udp.srcport",
            "udp.dstport",
            "gre.proto",
            "vxlan.vni",
            "geneve.vni",
            "gtp.teid",
            "mpls.label",
            "erspan.spanid",
            "pppoe.session_id",
            "vlan.id",
        )
    ),
)

DEVICE_PASS = PassSpec(
    name="device",
    display_filter="eth",
    fields=(
        "frame.number",
        "frame.time_epoch",
        "eth.src",
        "eth.src.oui_resolved",
        "eth.src_resolved",
        "ip.src",
        "ipv6.src",
    ),
)

PROTOCOLS_PASS = PassSpec(
    name="protocols",
    display_filter="frame",
    fields=("frame.len", "frame.protocols"),
)

FRAMES_PASS = PassSpec(
    name="frames",
    display_filter="frame",
    fields=(
        "frame.time_relative",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
    ),
)

SOFTWARE_PASS = PassSpec(
    name="software",
    display_filter="http.server || http.user_agent || ssh.protocol",
    fields=(
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "tcp.dstport",
        "http.server",
        "http.user_agent",
        "ssh.protocol",
    ),
)

OS_PASS = PassSpec(
    name="os",
    display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
    fields=("frame.time_epoch", "ip.src", "ip.ttl", "tcp.window_size_value"),
)

ARP_ICMP_PASS = PassSpec(
    name="arp_icmp",
    display_filter="arp.opcode == 2 || icmp.type == 5",
    fields=(
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "arp.opcode",
        "arp.src.hw_mac",
        "arp.src.proto_ipv4",
        "icmp.type",
        "icmp.code",
        "icmp.redir_gw",
    ),
)

CAPTURE_LOSS_PASS = PassSpec(
    name="capture_loss",
    display_filter="tcp.flags.ack == 1",
    fields=("frame.number", "frame.time_epoch", "tcp.analysis.lost_segment"),
)

MODBUS_PASS = PassSpec(
    name="modbus",
    display_filter="modbus",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "mbtcp.trans_id",
            "mbtcp.unit_id",
            "modbus.func_code",
            "modbus.exception_code",
        )
    ),
)
DNP3_PASS = PassSpec(
    name="dnp3",
    display_filter="dnp3",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "dnp3.src",
            "dnp3.dst",
            "dnp3.al.func",
            "dnp3.al.iin",
        )
    ),
)

#: RDP Negotiation fields via TPKT heuristic (#218).
#: Uses tcp.payload since RDP dissector availability varies by tshark version.
RDP_PASS = PassSpec(
    name="rdp",
    display_filter="tcp.port == 3389",
    fields=with_addr((
        "frame.time_epoch",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.payload",
    )),
)

#: PostgreSQL wire protocol for pgsql.log (#225): startup parameters (user, database),
#: the authentication method requested by the server, and simple-query text. Passwords are never extracted.
PGSQL_PASS = PassSpec(
    name="pgsql",
    display_filter="pgsql",
    fields=with_addr(("frame.time_epoch", "tcp.srcport", "tcp.dstport",
                      "pgsql.type", "pgsql.parameter_name", "pgsql.parameter_value",
                      "pgsql.authtype", "pgsql.query")),
)

#: Redis RESP protocol for redis.log (#225): raw TCP payload, parsed to extract the command name
#: and key. Passwords (AUTH argument) and command arguments are never logged.
RESP_PASS = PassSpec(
    name="resp",
    display_filter="resp && tcp.len > 0",
    fields=with_addr(("frame.time_epoch", "tcp.srcport", "tcp.dstport", "tcp.payload")),
)
SYSLOG_PASS = PassSpec(name="syslog", display_filter="syslog", fields=with_addr((
    "frame.time_epoch", "udp.srcport", "udp.dstport", "syslog.facility", "syslog.level", "syslog.version",
    "syslog.timestamp", "syslog.timestamp_rfc3164", "syslog.hostname", "syslog.appname", "syslog.procid",
    "syslog.msgid", "syslog.msg")))

VNC_PASS = PassSpec(
    name="vnc",
    display_filter="vnc",
    fields=with_addr((
        "frame.time_epoch",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "vnc.server_proto_ver",
        "vnc.client_proto_ver",
        "vnc.num_security_types",
        "vnc.security_type",
        "vnc.client_security_type",
        "vnc.auth_result",
        "vnc.auth_error",
        "vnc.desktop_name",
        "vnc.width",
        "vnc.height",
        "vnc.share_desktop_flag",
    )),
)

#: STUN (RFC 5389) on the well-known port; tshark exposes type and the XOR-decoded address (#224).
STUN_PASS = PassSpec(name="stun", display_filter="stun", fields=with_addr(("frame.time_epoch", "tcp.srcport", "tcp.dstport",
       "udp.srcport", "udp.dstport", "stun.type", "stun.att.family", "stun.att.ipv4", "stun.att.ipv6",
       "stun.att.port")))
#: RTSP requests and responses over TCP (#224).
RTSP_PASS = PassSpec(name="rtsp", display_filter="rtsp", fields=with_addr(("frame.time_epoch", "tcp.srcport", "tcp.dstport",
       "rtsp.method", "rtsp.url", "rtsp.status")))
#: BitTorrent DHT (UDP, heuristic) and peer-wire handshakes (TCP 6881-6889). The bt-dht
#: dissector exposes the bencoded message as a flat key/value sequence in bt-dht.bencoded.string;
#: the query type ("q"), transaction id ("t") and info_hash have no dedicated field, so the
#: log builder parses that sequence. The bittorrent handshake exposes bittorrent.info_hash and peer_id.
BT_DHT_PASS = PassSpec(
    name="bt-dht",
    display_filter="bt-dht || bittorrent",
    fields=with_addr((
        "frame.time_epoch",
        "udp.srcport",
        "udp.dstport",
        "tcp.srcport",
        "tcp.dstport",
        "udp.payload",
        "bt-dht.id",
        "bt-dht.port",
        "bittorrent.info_hash",
        "bittorrent.peer_id",
    )),
)

#: MQTT control packets for mqtt.log (#206): type, version, client id, user name, topic, CONNACK return code.
#: Never the password field.
MQTT_PASS = PassSpec(
    name="mqtt",
    display_filter="mqtt",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "mqtt.msgtype",
            "mqtt.ver",
            "mqtt.clientid",
            "mqtt.username",
            "mqtt.topic",
            "mqtt.conack.val",
        )
    ),
)

#: EtherNet/IP encapsulation and CIP service for enip.log (#206). No CIP payload data, only the service and class.
ENIP_PASS = PassSpec(
    name="enip",
    display_filter="enip",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "enip.command",
            "enip.session",
            "enip.status",
            "cip.service",
            "cip.rr",
            "cip.class",
        )
    ),
)

#: IEC 60870-5-104 APCI and ASDU header for iec104.log (#206). No information element values.
IEC104_PASS = PassSpec(
    name="iec104",
    display_filter="iec60870_104",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "iec60870_104.type",
            "iec60870_104.utype",
            "iec60870_asdu.typeid",
            "iec60870_asdu.causetx",
            "iec60870_asdu.addr",
            "iec60870_asdu.ioa",
        )
    ),
)

#: BACnet/IP BVLC function, APDU type, service choice and invoke id for bacnet.log (#206). No property values.
BACNET_PASS = PassSpec(
    name="bacnet",
    display_filter="bvlc || bacapp",
    fields=with_addr(
        (
            "frame.time_epoch",
            "udp.srcport",
            "udp.dstport",
            "bvlc.function",
            "bacapp.type",
            "bacapp.invoke_id",
            "bacapp.confirmed_service",
            "bacapp.unconfirmed_service",
        )
    ),
)

#: S7comm PDU header, function, item count and first item's area and DB for s7comm.log (#206). No data values.
S7COMM_PASS = PassSpec(
    name="s7comm",
    display_filter="s7comm",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "s7comm.header.rosctr",
            "s7comm.param.func",
            "s7comm.param.itemcount",
            "s7comm.param.item.area",
            "s7comm.param.item.db",
        )
    ),
)

#: OPC UA binary transport type and service node id for opcua.log (#206). No payload values.
#: One batched pass for the ICS command detector (#206): Modbus, DNP3, S7comm and IEC 60870-5-104 command fields.
ICS_CONTROL_PASS = PassSpec(
    name="ics_control",
    display_filter="modbus || dnp3 || s7comm || iec60870_104",
    fields=with_addr(
        (
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "modbus.func_code",
            "dnp3.al.func",
            "s7comm.header.rosctr",
            "s7comm.param.func",
            "iec60870_asdu.typeid",
            "iec60870_asdu.causetx",
        )
    ),
)

OPCUA_PASS = PassSpec(
    name="opcua",
    display_filter="opcua",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "opcua.transport.type",
            "opcua.servicenodeid.numeric",
        )
    ),
)

#: tshark expert info at warning and error level: malformed packets, bad lengths, broken checksums...
WEIRD_PASS = PassSpec(
    name="weird",
    display_filter="_ws.expert && frame",
    fields=with_addr(
        (
            "frame.time_epoch",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "_ws.expert.message",
            "_ws.expert.severity",
            "_ws.expert.group",
            "ip.checksum.status",
            "tcp.checksum.status",
            "udp.checksum.status",
            "icmp.checksum.status",
        )
    ),
)

#: tshark leaves checksums unverified by default; the conn and weird passes turn checking on (#209).
CHECKSUM_ARGS: tuple[str, ...] = (
    "-o",
    "ip.check_checksum:TRUE",
    "-o",
    "tcp.check_checksum:TRUE",
    "-o",
    "udp.check_checksum:TRUE",
)

#: Field prefixes that are transport- or link-layer only (no application dissection).
_TRANSPORT_PREFIXES: frozenset[str] = frozenset({
    "frame", "eth", "ip", "ipv6", "tcp", "udp", "arp", "icmp", "igmp",
    "gre", "vlan", "vxlan", "geneve", "gtp", "mpls", "pppoe", "erspan",
})

#: Application-protocol tokens that, if present in a display filter, mean the pass
#: dissects application-layer data and must keep tcp sequence analysis on.
_APP_PROTOCOLS: frozenset[str] = frozenset({
    "tls", "dtls", "http", "dns", "sip", "sdp", "rtp", "rtcp", "ssh", "quic",
    "ftp", "smtp", "smb", "smb2", "imf", "kerberos", "ntlmssp", "ntlm",
    "modbus", "mbtcp", "dnp3", "mqtt", "enip", "cip", "iec60870_104", "bvlc", "bacapp", "s7comm", "opcua", "telnet", "dhcp", "dhcpv6",
    "tftp", "ntp", "snmp", "mysql", "ldap", "imap", "pop", "radius", "ike",
    "nfs",
})

def _is_transport_only(spec: PassSpec, fields: tuple[str, ...]) -> bool:
    """True when the pass reads no tcp.analysis.* / _ws.expert.* fields, all of
    its fields are transport/link-layer, and its display filter names no
    application protocol (issue #329)."""
    # Reads tcp.analysis.* or _ws.expert.* -> analysis produces those values.
    if any(f.startswith("tcp.analysis.") or f.startswith("_ws.expert.") for f in fields):
        return False
    # Any field outside the transport/link-layer set -> app-layer work.
    if any(f.split(".")[0] not in _TRANSPORT_PREFIXES for f in fields):
        return False
    # Display filter mentioning an app protocol -> app-layer filter.
    if spec.display_filter:
        # Split on operators and whitespace to get bare field/protocol tokens.
        for token in re.split(r"[\s()=<>!&|]+", spec.display_filter):
            if not token:
                continue
            root = token.split(".")[0]
            if root in _APP_PROTOCOLS:
                return False
    return True

#: Every TCP/UDP payload, for the user-supplied signature engine (#201). Only run when signatures are given.
PAYLOAD_PASS = PassSpec(
    name="payload",
    display_filter="tcp.len > 0 || udp.length > 8",
    fields=with_addr(
        (
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "tcp.stream",
            "tcp.flags",
            "tcp.payload",
            "udp.payload",
        )
    ),
)

PASSES: dict[str, PassSpec] = {
    p.name: p
    for p in (
        BASE_PASS,
        TLS_PASS,
        DTLS_PASS,
        HTTP_PASS,
        HTTP2_PASS,
        DNS_PASS,
        SIP_PASS,
        RTP_PASS,
        SSH_PASS,
        QUIC_PASS,
        SERVICE_PASS,
        TELNET_PASS,
        IPV6_ADDR_PASS,
        CONN_PASS,
        DHCP_PASS,
        NBNS_PASS,
        DHCPV6_PASS,
        FTP_PASS,
        SMTP_PASS,
        SMB_PASS,
        WEIRD_PASS,
        PAYLOAD_PASS,
        KERBEROS_PASS,
        NTLM_PASS,
        RADIUS_PASS,
        MODBUS_PASS,
        DNP3_PASS,
        PGSQL_PASS,
        RESP_PASS,
        VNC_PASS,
        STUN_PASS,
        RTSP_PASS,
        BT_DHT_PASS,
        MQTT_PASS,
        ENIP_PASS,
        IEC104_PASS,
        BACNET_PASS,
        S7COMM_PASS,
        OPCUA_PASS,
        ICS_CONTROL_PASS,
        TUNNEL_PASS,
        SYSLOG_PASS,
        PROTOCOLS_PASS,
        FRAMES_PASS,
        SOFTWARE_PASS,
        OS_PASS,
        ARP_ICMP_PASS,
        CAPTURE_LOSS_PASS,
        DEVICE_PASS,
        RDP_PASS,
    )
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

#: In --fast mode, passes whose protocol normally lives on a well-known port are
#: pre-split with one of these BPF filters so tshark only touches the small
#: sub-capture. Protocols on non-standard ports are not covered (issue #334).
FAST_PASS_BPF: dict[str, str] = {
    "dns": "port 53",
    "sip": "udp port 5060",
    "ssh": "tcp port 22",
    "telnet": "tcp port 23",
    "smb": "tcp port 445",
    "services": "port 123 or port 23 or port 445 or port 21 or port 69 or port 161 or port 143 or port 110 or port 25 or port 389 or port 3306",
}


def _fill_skip_protocols() -> dict[str, PassSpec]:
    """Derive ``skip_protocols`` for every pass that has a display filter but no explicit set (#328).

    A pass with ``skip_protocols = None`` is never skipped (``base``, ``protocols``,
    ``frames``, ``device`` read the whole frame set).  A pass whose filter references
    only transport layers has no skip protocols either -- it would run on every capture.
    """
    from dataclasses import replace

    out: dict[str, PassSpec] = {}
    for name, spec in PASSES.items():
        if spec.skip_protocols is None and spec.display_filter:
            out[name] = replace(spec, skip_protocols=protocols_in_filter(spec.display_filter))
        else:
            out[name] = spec
    return out


#: Passes whose protocol tokens are absent from a capture can be skipped (#328).
SKIP_PROTOCOLS: dict[str, tuple[str, ...]] = {
    name: (spec.skip_protocols or ()) for name, spec in _fill_skip_protocols().items()
}


@lru_cache(maxsize=1)
def tshark_path() -> str:
    found = shutil.which("tshark")
    if not found:
        raise TsharkMissingError(
            "tshark not found on PATH. Install Wireshark/tshark (macOS: brew install wireshark)."
        )
    return found


@lru_cache(maxsize=1)
def tshark_version() -> str:
    """Short version string, e.g. ``4.6.6 (Git commit ...)``."""
    out = subprocess.run([tshark_path(), "-v"], capture_output=True, text=True, check=False).stdout
    first = out.splitlines()[0] if out else "unknown"
    return first.replace("TShark (Wireshark)", "").strip()


@lru_cache(maxsize=1)
def valid_fields() -> frozenset[str]:
    """Every field name this tshark build exposes (``-G fields``, 3rd column)."""
    out = subprocess.run([tshark_path(), "-G", "fields"], capture_output=True, text=True, check=False).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            name = parts[2].strip()
            if name:
                names.add(name)
    return frozenset(names)


@lru_cache(maxsize=1)
def protocol_names() -> frozenset[str]:
    """Short protocol names usable in a display filter (``-G protocols``)."""
    out = subprocess.run(
        [tshark_path(), "-G", "protocols"], capture_output=True, text=True, check=False
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip():
            names.add(parts[2].strip())
    return frozenset(names)


@lru_cache(maxsize=1)
def default_prefs() -> frozenset[str]:
    """Preference names this tshark build knows about (``-G defaultprefs``).

    Every entry in that dump is commented out with ``#``, so the marker is
    stripped before the name is collected.
    """
    out = subprocess.run(
        [tshark_path(), "-G", "defaultprefs"], capture_output=True, text=True, check=False
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        line = line.lstrip("#").strip()
        if not line:
            continue
        name = line.split(None, 1)[0].rstrip(":")
        if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            names.add(name)
    return frozenset(names)


WANTED_PREFS: tuple[str, ...] = (
    "tcp.desegment_tcp_streams",
    "tcp.desegment_tcp_streams_lua",
    "tls.desegment_ssl_records",
    "tls.desegment_ssl_application_data",
    "dtls.desegment_dtls_records",
    "dtls.desegment_app_data",
    "ip.defragment",
    "ipv6.defragment",
)

#: Preferences rejected by the running tshark, discovered at runtime.
_UNSUPPORTED_PREFS: set[str] = set()


def _supported_prefs() -> tuple[str, ...]:
    known = default_prefs()
    prefs = WANTED_PREFS if not known else tuple(p for p in WANTED_PREFS if p in known)
    return tuple(p for p in prefs if p not in _UNSUPPORTED_PREFS)


@lru_cache(maxsize=1)
def capture_interface_types() -> list[str]:
    """Physical interface types present in this tshark build (e.g. EN10MB)."""
    out = subprocess.run([tshark_path(), "-G", "values"], capture_output=True, text=True, check=False)
    return out.stdout.splitlines()


def file_sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def cache_dir() -> Path:
    """PCAP_DOCTOR_CACHE, else the older PCAP_FORENSICS_CACHE (still honoured), else ~/.cache/pcap-doctor."""
    env = os.environ.get("PCAP_DOCTOR_CACHE") or os.environ.get("PCAP_FORENSICS_CACHE")
    base = Path(env) if env else Path.home() / ".cache" / "pcap-doctor"
    base.mkdir(parents=True, exist_ok=True)
    return base


def split_multi(value: str) -> list[str]:
    return [chunk for chunk in value.split(AGG) if chunk != ""]


def to_int(value: str, base: int = 10) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def to_int_list(values: list[str], base: int = 10) -> list[int]:
    out: list[int] = []
    for v in values:
        for part in v.split(","):
            parsed = to_int(part.strip(), base)
            if parsed is not None:
                out.append(parsed)
    return out


def to_int_auto(value: str) -> int | None:
    """Parse an integer that tshark may print in hex (``0xd2bd4e3e``) or decimal."""
    value = value.strip()
    if not value:
        return None
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def to_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def to_bool01(value: str) -> bool | None:
    """tshark renders boolean fields as 1/0 *and* as True/False depending on build."""
    value = value.strip().lower()
    if value in {"1", "true", "set"}:
        return True
    if value in {"0", "false", "unset"}:
        return False
    return None


def parse_cipher_ids(value: str) -> list[int]:
    """Parse a tshark cipher list (``0x1301,0x1302``) into ints.

    Only ``0x``-prefixed tokens are hex. tshark always emits the prefix, and
    guessing that a bare ``4865`` is hex silently turns 0x1301 into 0x4865.
    """
    out: list[int] = []
    for part in re.split(r"[,\s]+", value.strip()):
        part = part.strip()
        if not part:
            continue
        try:
            if part.lower().startswith("0x"):
                out.append(int(part, 16))
            else:
                out.append(int(part))
        except ValueError:
            try:
                out.append(int(part, 16))
            except ValueError:
                continue
    return out


def parse_hex_bits(value: str) -> int | None:
    """RSA public-key modulus (hex) -> bit length.

    Measured in bytes, not stripped nibbles: a modulus with a leading zero
    nibble is still the advertised key size, and a real modulus is never all
    zeros.
    """
    value = value.strip().replace(":", "")
    if not value or not _HEX_RE.match(value):
        return None
    if len(value) % 2 == 1 and value[0] == "0":
        value = value[1:]
    if not value:
        return None
    return max(1, (len(value) // 2) * 8)


#: DER encodings of the named-curve OIDs, mapped to the curve's field size.
#: Used when tshark gives us the SubjectPublicKeyInfo blob but no modulus
#: (EC keys have no modulus, so key size has to come from the curve).
EC_CURVE_OIDS: dict[str, int] = {
    "2a8648ce3d030105": 192,  # 1.2.840.10045.3.1.1  prime192v1
    "2a8648ce3d030107": 256,  # 1.2.840.10045.3.1.7  prime256v1 / secp256r1
    "2b81040022": 224,  # 1.3.132.0.33  secp224r1
    "2b81040023": 384,  # 1.3.132.0.34  secp384r1
    "2b81040024": 521,  # 1.3.132.0.35  secp521r1
}


def public_key_bits(modulus_hex: str = "", spki_hex: str = "") -> int | None:
    """Best-effort public-key size: RSA modulus first, then the EC curve OID."""
    if modulus_hex:
        bits = parse_hex_bits(modulus_hex)
        if bits:
            return bits
    blob = (spki_hex or "").strip().replace(":", "").lower()
    if blob and _HEX_RE.match(blob):
        for oid, bits in EC_CURVE_OIDS.items():
            if oid in blob:
                return bits
    return None


class TsharkRunner:
    """Executes passes over one capture, with a content-addressed disk cache."""

    def __init__(
        self,
        pcap: Path,
        *,
        use_cache: bool = True,
        timeout: int = 600,
        extra_args: tuple[str, ...] = (),
        fast: bool = False,
        jobs: int | None = None,
    ) -> None:
        self.pcap = pcap
        self.timeout = timeout
        self.use_cache = use_cache
        self.extra_args = extra_args
        self.fast = fast
        self._jobs = jobs
        self.version = tshark_version()
        self.sha = file_sha256(pcap) if pcap.is_file() else "unknown"
        self.stats: dict[str, dict[str, int | float | str]] = {}
        self.dropped_fields: list[str] = []
        self.skipped_passes: list[str] = []
        self._field_blacklist: set[str] = set()
        self._banned_protocols: set[str] = set()
        self._seen_protocols: set[str] | None = None  # populated from the base pass; None until then
        # ponytail: every prefetched pass stays in memory until the build ends; pop on read if huge captures OOM.
        self._prefetched: dict[tuple[str, tuple[str, ...]], list[Row]] = {}
        self._fast_subs: dict[str, Path] | None = None
        self._fast_fallback_note: str | None = None

    # -- internals ---------------------------------------------------------
    def _collect_protocols(self, rows: list[Row]) -> None:
        """Populate the protocol set from the base pass's ``frame.protocols`` column (#328)."""
        seen: set[str] = set()
        for row in rows:
            for chunk in row.get("frame.protocols", []):
                seen.update(chunk.split(":"))
        self._seen_protocols = seen

    def _should_skip(self, pass_name: str) -> bool:
        """True when the pass's protocol tokens are all absent from the capture (#328).

        A pass with no skip protocols (``base``, ``conn``, ...) always runs.
        Until the base pass has been read, the protocol set is unknown and every
        pass runs, so the first caller (always ``base``) is never skipped.
        """
        need = SKIP_PROTOCOLS.get(pass_name, ())
        if not need or self._seen_protocols is None:
            return False
        return not (set(need) & self._seen_protocols)

    def usable_fields(self, spec: PassSpec) -> tuple[str, ...]:
        """Drop fields this tshark build does not know, recording the drift."""
        known = valid_fields()
        if not known:
            return spec.fields
        keep: list[str] = []
        for field in spec.fields:
            if field in self._field_blacklist:
                dropped = f"{spec.name}:{field}"
                if dropped not in self.dropped_fields:
                    self.dropped_fields.append(dropped)
                continue
            # _ws.col.* display columns are not listed by `-G fields` but are valid.
            if field in known or field.startswith("_ws."):
                keep.append(field)
                continue
            dropped = f"{spec.name}:{field}"
            if dropped not in self.dropped_fields:
                self.dropped_fields.append(dropped)
        return tuple(keep)

    def _cache_file(
        self, pass_name: str, extra_args: tuple[str, ...] = (), pcap_sha: str | None = None
    ) -> Path:
        args = self.extra_args + extra_args
        suffix = "-" + hashlib.sha256("\x1f".join(args).encode()).hexdigest()[:8] if args else ""
        sha = pcap_sha or self.sha
        return cache_dir() / sha[:16] / f"{self.version.split()[0]}-{pass_name}{suffix}.json"

    def _filter_for(self, spec: PassSpec) -> str | None:
        """Drop protocol tokens this tshark build does not know, recording the drift."""
        if not spec.display_filter:
            return None
        if not protocol_names():
            return spec.display_filter
        kept: list[str] = []
        known = protocol_names()
        for token in spec.display_filter.split("||"):
            token = token.strip()
            if not token:
                continue
            if token in self._banned_protocols:
                continue
            if " " in token or any(op in token for op in "()=<>!"):
                kept.append(token)  # expression, not a bare protocol name: keep as written
                continue
            if token in known or token.split(".")[0] in known:
                kept.append(token)
                continue
            dropped = f"{spec.name}:filter!{token}"
            if dropped not in self.dropped_fields:
                self.dropped_fields.append(dropped)
        return " || ".join(kept) if kept else None

    def _command(
        self, spec: PassSpec, extra_args: tuple[str, ...] = (), pcap: Path | None = None
    ) -> list[str]:
        cmd = [*_low_priority_prefix(), tshark_path(), "-r", str(pcap or self.pcap), "-n", "-l"]
        display_filter = self._filter_for(spec)
        if display_filter:
            cmd += ["-Y", display_filter]
        if spec.fields:
            fields = self.usable_fields(spec)
            cmd += [
                "-T",
                "fields",
                "-E",
                f"separator={TAB}",
                "-E",
                "occurrence=a",
                "-E",
                f"aggregator={AGG}",
                "-E",
                "header=y",
                "-E",
                "quote=n",
            ]
            for field in fields:
                cmd += ["-e", field]
        # tcp sequence analysis is expensive (issue #329); disable it only for
        # transport-only passes: every field is a transport/frame-layer field AND
        # the display filter names no application protocol. Passes that read any
        # tcp.analysis.* or _ws.expert.* field must keep analysis on (those values
        # are produced by the analysis layer). Passes with an application filter
        # (ftp, http, tls, ...) must also keep analysis on, because with it off
        # tshark re-hands retransmitted segments to the app dissector, producing
        # duplicate application-row findings.
        if _is_transport_only(spec, fields):
            cmd += ["-o", "tcp.analyze_sequence_numbers:FALSE"]
        for pref in _supported_prefs():
            cmd += ["-o", f"{pref}:TRUE"]
        cmd += list(self.extra_args) + list(extra_args)
        return cmd

    def _fast_sub(self, pass_name: str, bpf: str) -> Path | None:
        """Return a tcpdump-filtered sub-capture for a pass, or None if tcpdump is unavailable.

        The sub-captures live under the cache dir (deterministic, keyed by the main
        capture's sha and the BPF filter) so they survive across runs.
        """
        if self._fast_subs is not None and pass_name in self._fast_subs:
            return self._fast_subs[pass_name]
        if self._fast_subs is None:
            self._fast_subs = {}
        sub = (
            cache_dir()
            / f"{self.sha[:16]}-fast-{hashlib.sha256(bpf.encode()).hexdigest()[:8]}"
            / f"{pass_name}.pcap"
        )
        if sub.exists():
            self._fast_subs[pass_name] = sub
            return sub
        path = shutil.which("tcpdump")
        if path is None:
            self._fast_fallback_note = "tcpdump not found; --fast fell back to scanning the full capture"
            return None
        sub.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [path, "-r", str(self.pcap), "-w", str(sub), bpf],
            capture_output=True,
            text=True,
            check=False,
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            self._fast_fallback_note = (
                f"tcpdump failed ({proc.stderr.strip()[:200]}); --fast fell back to scanning the full capture"
            )
            sub.unlink(missing_ok=True)
            return None
        self._fast_subs[pass_name] = sub
        return sub

    def _pcap_for(self, spec: PassSpec) -> tuple[Path, str]:
        """The pcap file and its sha for this pass.

        In fast mode, passes whose protocol lives on a well-known port run against
        a tcpdump BPF-filtered sub-capture; everything else (and everything in
        normal mode) runs against the full capture.
        """
        if self.fast:
            bpf = FAST_PASS_BPF.get(spec.name)
            if bpf:
                sub = self._fast_sub(spec.name, bpf)
                if sub is not None:
                    return sub, file_sha256(sub)
        return self.pcap, self.sha

    def _run(self, spec: PassSpec, extra_args: tuple[str, ...] = ()) -> list[Row]:
        fields = self.usable_fields(spec)
        pcap, pcap_sha = self._pcap_for(spec)
        cache = self._cache_file(spec.name, extra_args, pcap_sha=pcap_sha)
        if self.use_cache and cache.exists():
            try:
                payload = json.loads(cache.read_text())
                if (
                    payload.get("sha") == pcap_sha
                    and payload.get("fields") == list(fields)
                    and payload.get("extra") == list(extra_args)
                ):
                    rows = [Row(r) for r in payload["rows"]]
                    if spec.name == "base":
                        self._collect_protocols(rows)
                    self.stats[spec.name] = {"rows": len(rows), "cached": 1}
                    return rows
            except (json.JSONDecodeError, KeyError, TypeError):
                cache.unlink(missing_ok=True)

        # Skip the tshark process entirely when none of the pass's protocols appear
        # in the capture.  A skipped pass yields the same empty rows it would have
        # produced, so reports stay byte-identical (#328).
        # Extra args (decode-as, TLS-key decryption) can reveal protocols that the
        # base pass cannot see, so never skip a pass that is invoked with them.
        if not extra_args and self._should_skip(spec.name):
            self.skipped_passes.append(spec.name)
            self.stats[spec.name] = {"rows": 0, "cached": 0, "skipped": 1}
            return []

        cmd = self._command(spec, extra_args, pcap=pcap)
        # Issue #331: run tshark at low priority so the machine stays responsive.
        low_prio = _low_priority_kwargs()
        for _attempt in range(6):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=self.timeout, **low_prio)
            if proc.returncode == 0:
                break
            bad_pref = re.search(r'-o flag "([^"]+)" specifies unknown preference', proc.stderr)
            if bad_pref:
                offending = bad_pref.group(1).split(":", 1)[0]
                if offending not in _UNSUPPORTED_PREFS:
                    _UNSUPPORTED_PREFS.add(offending)
                    cmd = self._command(spec, extra_args, pcap=pcap)
                    continue
            bad_proto = re.search(
                r'"([A-Za-z0-9_.-]+)" is not a valid protocol or protocol field', proc.stderr
            )
            if bad_proto:
                offender = bad_proto.group(1)
                self._banned_protocols.add(offender)
                cmd = self._command(spec, extra_args, pcap=pcap)
                continue
            bad_field = re.search(r"^\t(\S+) is not a valid field", proc.stderr, re.MULTILINE)
            if bad_field:
                field = bad_field.group(1)
                dropped = f"{spec.name}:{field}"
                if dropped not in self.dropped_fields:
                    self.dropped_fields.append(dropped)
                self._field_blacklist.add(field)
                cmd = self._command(spec, extra_args, pcap=pcap)
                continue
            raise TsharkRunError(
                f"tshark pass {spec.name!r} failed (exit {proc.returncode}):\n"
                f"{proc.stderr.strip()[:2000]}\ncmd: {' '.join(cmd)}"
            )
        else:
            raise TsharkRunError(f"tshark pass {spec.name!r} kept hitting unknown preferences")
        rows = self._parse(proc.stdout, fields)
        if spec.name == "base":
            self._collect_protocols(rows)
        if self.use_cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"sha": pcap_sha, "fields": list(fields), "extra": list(extra_args), "rows": rows})
            )
            tmp.replace(cache)
        self.stats[spec.name] = {"rows": len(rows), "cached": 0}
        return rows

    @staticmethod
    def _parse(stdout: str, fields: tuple[str, ...]) -> list[Row]:
        lines = stdout.splitlines()
        if not lines:
            return []
        header = lines[0].split(TAB)
        if header == list(fields) or (header and header[0] == "frame.number"):
            names = header
            body = lines[1:]
        else:
            names = list(fields)
            body = lines
        rows: list[Row] = []
        for line in body:
            if not line.strip():
                continue
            parts = line.split(TAB)
            row: Row = {}
            for i, name in enumerate(names):
                raw = parts[i] if i < len(parts) else ""
                row[name] = split_multi(raw)
            rows.append(row)
        return rows

    # -- public API --------------------------------------------------------
    def run(self, pass_name: str, extra_args: tuple[str, ...] = ()) -> list[Row]:
        spec = PASSES.get(pass_name)
        if spec is None:
            raise KeyError(f"unknown pass {pass_name!r}; known: {sorted(PASSES)}")
        if (pass_name, extra_args) in self._prefetched:
            return self._prefetched[(pass_name, extra_args)]
        return self._run(spec, extra_args)

    def prefetch(self, jobs: dict[str, tuple[str, ...]], *, count: int | None = None) -> None:
        """Run independent passes (name -> per-call extra args) concurrently; ``run`` then returns their rows.

        Each pass is its own tshark process re-reading the capture, so threads are enough: they only wait.

        The ``base`` pass is always run first so its ``frame.protocols`` column can
        seed the protocol set (#328).  Once that set is known, every other pass
        whose protocols are absent from the capture is skipped instead of
        launched, saving a full re-dissection.
        """
        for name in jobs:
            if name not in PASSES:
                raise KeyError(f"unknown pass {name!r}; known: {sorted(PASSES)}")
        valid_fields(), protocol_names(), default_prefs()  # warm the `tshark -G` lookups once, not per thread
        # Run base first so the protocol set is available for skip decisions.
        remaining: dict[str, tuple[str, ...]] = dict(jobs)
        if "base" in remaining:
            base_args = remaining.pop("base")
            self._prefetched[("base", base_args)] = self._run(PASSES["base"], base_args)
        # Remaining passes run concurrently; _run skips each whose protocols are absent.
        if not remaining:
            return
        # Issue #331: cap concurrency via --jobs / PCAP_DOCTOR_JOBS / CPU-based default.
        limit = count if count is not None else worker_count(self._jobs)
        limit = max(1, min(limit, len(remaining)))
        with ThreadPoolExecutor(max_workers=limit) as pool:
            futures = {
                (name, args): pool.submit(self._run, PASSES[name], args) for name, args in remaining.items()
            }
        for key, future in futures.items():
            self._prefetched[key] = future.result()

    def all_passes(self) -> dict[str, list[Row]]:
        out = {}
        for name, spec in PASSES.items():
            out[name] = self._run(spec)
        return out

    def fast_fallback_note(self) -> str | None:
        """Return the fallback note if tcpdump was missing/failed, else None."""
        return self._fast_fallback_note

    @staticmethod
    def rtp_decode_args(ports: list[int]) -> tuple[str, ...]:
        """tshark only dissects RTP on well-known ports; SDP tells us the rest.

        Without this, media on dynamic ports shows up as plain UDP and the
        SRTP/plaintext verdict is impossible to make.
        """
        return tuple(f"-d udp.port=={port},rtp" for port in sorted(set(ports)) if 0 < port < 65536)

    def capture_stats(self) -> dict[str, str]:
        """capinfos-style facts, derived from the base pass (no extra process)."""
        base = self.run("base")
        packets = len(base)
        total_bytes = 0
        first = last = 0.0
        for row in base:
            for v in row.get("frame.len", []):
                total_bytes += int(v) if v.isdigit() else 0
            ts = to_float(row["frame.time_epoch"][0]) if row.get("frame.time_epoch") else None
            if ts is not None:
                if first == 0.0:
                    first = ts
                last = max(last, ts)
        return {
            "packets": str(packets),
            "bytes": str(total_bytes),
            "first": f"{first:.6f}",
            "last": f"{last:.6f}",
            "duration": f"{max(0.0, last - first):.6f}",
        }
