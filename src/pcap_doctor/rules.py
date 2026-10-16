"""Catalog of every finding code: its detector, user-facing category and a short title (issue #47).

This is the only place categories come from. A detector that emits a new code must add it here;
``tests/test_rules_catalog.py`` fails otherwise.
"""

from __future__ import annotations

from typing import NamedTuple

#: Display order of categories in summaries. "Other" catches codes missing from the catalog.
CATEGORIES: tuple[str, ...] = ("Crypto", "Credentials", "Cleartext", "DNS", "SSH & QUIC", "Voice", "Network", "Signatures", "SMB", "Other")


class Rule(NamedTuple):
    code: str
    detector: str
    category: str
    title: str


_TLS = "d1.tls_cipher"
_TRANSPORT = "d2.transport_exposure"
_VOICE = "d3.sip_rtp"
_DNS_QUIC_SSH = "d4.dns_quic_ssh"
_SIGNATURES = "d9.user_signatures"
_SMB = "d10.smb"
_BRUTE = "d11.brute_force"
_ARP = "d12.arp_icmp"
_CAPTURE_LOSS = "d13.capture_loss"
_HOSTNAMES = "d14.hostnames"
_HTTP_HEADERS = "d15.http_headers"
_WEB_ATTACK = "d16.web_attack"
_ECH_0RTT = "d17.ech_early_data"
_VPN = "d19.vpn_handshakes"
_HTTP2 = "d5.http2"

RULES: dict[str, Rule] = {
    rule.code: rule
    for rule in (
        Rule("TLS_VERSION_DEPRECATED", _TLS, "Crypto", "Deprecated TLS/DTLS version negotiated"),
        Rule("TLS_LEGACY_RECORD_VERSION", _TLS, "Crypto", "Legacy record-layer version field"),
        Rule("TLS_CIPHER_UNKNOWN", _TLS, "Crypto", "Cipher suite missing from the registry"),
        Rule("TLS_CIPHER_WEAK", _TLS, "Crypto", "Weak or prohibited cipher suite negotiated"),
        Rule("TLS_OFFERS_WEAK_CIPHERS", _TLS, "Crypto", "Client offers weak cipher suites"),
        Rule("TLS_NO_FORWARD_SECRECY", _TLS, "Crypto", "No forward secrecy"),
        Rule("TLS_KEY_IN_FIRMWARE", _TLS, "Crypto", "Server private key ships in the firmware"),
        Rule("TLS_CERT_EXPIRED", _TLS, "Crypto", "Certificate already expired during the capture"),
        Rule("TLS_CERT_EXPIRED_NOW", _TLS, "Crypto", "Certificate has expired since the capture"),
        Rule("TLS_CERT_EXPIRING", _TLS, "Crypto", "Certificate close to expiry"),
        Rule("TLS_CERT_WEAK_KEY", _TLS, "Crypto", "Weak certificate key"),
        Rule("TLS_CERT_WEAK_SIGALG", _TLS, "Crypto", "Weak certificate signature algorithm"),
        Rule("TLS_CERT_NOT_YET_VALID", _TLS, "Crypto", "Certificate not yet valid"),
        Rule("TLS_SNI_CERT_MISMATCH", _TLS, "Crypto", "SNI not covered by the certificate"),
        Rule("TLS_NO_EXTENDED_MASTER_SECRET", _TLS, "Crypto", "No extended master secret (RFC 7627)"),
        Rule("TLS_WEAK_DH_GROUP", _TLS, "Crypto", "Weak finite-field DH group (Logjam)"),
        Rule("TLS_NO_OCSP_STAPLE", _TLS, "Crypto", "OCSP response not stapled"),
        Rule("TLS_NO_SCT", _TLS, "Crypto", "Certificate without Certificate Transparency SCTs"),
        Rule("TLS_SELF_SIGNED_CHAIN", _TLS, "Crypto", "Self-signed certificate chain"),
        Rule("TLS_FATAL_ALERT", _TLS, "Crypto", "Fatal TLS alert"),
        Rule("TLS_WARNING_ALERT", _TLS, "Crypto", "TLS warning alert"),
        Rule("TLS_HANDSHAKE_TRUNCATED", _TLS, "Crypto", "Truncated TLS handshake"),
        Rule("TLS_JA3_FLEET", _TLS, "Crypto", "Client JA3 fingerprint fleet"),
        Rule("TLS_HEARTBLEED_PROBE", _TLS, "Crypto", "Heartbleed probe (CVE-2014-0160)"),
        Rule("TLS_COMPRESSION_ENABLED", _TLS, "Crypto", "TLS compression enabled (CRIME)"),
        Rule("TLS_SERVER_CIPHER_PREFERENCE", _TLS, "Crypto", "Server imposes its own cipher preference order"),
        Rule("TLS_INSECURE_RENEGOTIATION", _TLS, "Crypto", "Insecure TLS renegotiation"),
        Rule("CLEARTEXT_CREDENTIAL", _TRANSPORT, "Credentials", "Credential sent in cleartext"),
        Rule("HTTP_BASIC_AUTH", _TRANSPORT, "Credentials", "HTTP Basic authentication"),
        Rule("HTTP_CLEARTEXT_AUTH", _TRANSPORT, "Credentials", "HTTP authentication over cleartext"),
        Rule("HTTP_CLEARTEXT", _TRANSPORT, "Cleartext", "HTTP (or a firmware download) without TLS"),
        Rule("HTTP_COOKIE_NO_SECURE", _TRANSPORT, "Credentials", "Cookie without the Secure flag"),
        Rule("CLEARTEXT_SERVICE", _TRANSPORT, "Cleartext", "Cleartext service"),
        Rule("SERVICE_ON_ODD_PORT", _TRANSPORT, "Network", "Service on a non-standard port"),
        Rule("SYN_SCAN_SHAPE", _TRANSPORT, "Network", "Unanswered-SYN scan shape"),
        Rule("PORT_SCAN_VERTICAL", _TRANSPORT, "Network", "Vertical port scan"),
        Rule("PORT_SCAN_HORIZONTAL", _TRANSPORT, "Network", "Horizontal port scan"),
        Rule("BEACONING_SHAPE", _TRANSPORT, "Network", "Beaconing (regular callbacks)"),
        Rule("SIP_CLEARTEXT_SIGNALLING", _VOICE, "Voice", "Cleartext SIP signalling"),
        Rule("SDP_NO_CRYPTO_ATTR", _VOICE, "Voice", "SDP offered without SRTP keys"),
        Rule("RTP_MEDIA_UNPROTECTED", _VOICE, "Voice", "Unprotected RTP media"),
        Rule("RTP_VOLUME_ANOMALY", _VOICE, "Voice", "RTP media volume anomaly"),
        Rule("DNS_CLEARTEXT", _DNS_QUIC_SSH, "DNS", "Cleartext DNS"),
        Rule("DNS_TUNNEL_SHAPE", _DNS_QUIC_SSH, "DNS", "DNS tunnelling shape"),
        Rule("DNS_EXTERNAL_RESOLVER", _DNS_QUIC_SSH, "DNS", "External DNS resolver in use"),
        Rule("QUIC_PAYLOAD_OPAQUE", _DNS_QUIC_SSH, "SSH & QUIC", "QUIC payload opaque without a keylog"),
        Rule("SSH_WEAK_KEX", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH key exchange offered"),
        Rule("SSH_WEAK_CIPHER", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH cipher offered"),
        Rule("SSH_WEAK_MAC", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH MAC offered"),
        Rule("SSH_WEAK_HOSTKEY", _DNS_QUIC_SSH, "SSH & QUIC", "Weak SSH host-key algorithm offered"),
        Rule("SSH_TERRAPIN_EXPOSED", _DNS_QUIC_SSH, "SSH & QUIC", "Terrapin (CVE-2023-48795) exposure"),
        Rule("SMB1_IN_USE", _SMB, "SMB", "SMBv1 in use"),
        Rule("SMB_SIGNING_NOT_REQUIRED", _SMB, "SMB", "SMB signing not required by the server"),
        Rule("SMB_NULL_SESSION", _SMB, "SMB", "Anonymous (null) SMB session"),
        Rule("SMB_ADMIN_SHARE_ACCESS", _SMB, "SMB", "Administrative share accessed"),
        Rule("SMB_REMOTE_EXEC_PIPE", _SMB, "SMB", "Remote execution pipe opened over SMB"),
        Rule("SMB_EXECUTABLE_ON_SHARE", _SMB, "SMB", "Executable opened on an SMB share"),
        Rule("SIGNATURE_MATCH", _SIGNATURES, "Signatures", "User-supplied signature matched"),
        Rule("BRUTE_FORCE_SUSPECTED", _BRUTE, "Credentials", "Password guessing (repeated failed logins)"),
        Rule("ARP_SPOOFING_SUSPECTED", _ARP, "Network", "ARP spoofing suspected"),
        Rule("ICMP_REDIRECT", _ARP, "Network", "ICMP redirect seen"),
        Rule("CAPTURE_LOSS", _CAPTURE_LOSS, "Network", "Capture loss"),
        Rule("INTERESTING_HOSTNAME", _HOSTNAMES, "DNS", "Sensitive hostname (login/admin panel) exposed in cleartext"),
        Rule("HTTP_MISSING_SECURITY_HEADERS", _HTTP_HEADERS, "Network", "Missing HTTP security headers"),
        Rule("HTTP_WEB_ATTACK_SQLI", _WEB_ATTACK, "Cleartext", "SQL injection in an HTTP request URI"),
        Rule("HTTP_WEB_ATTACK_XSS", _WEB_ATTACK, "Cleartext", "Cross-site scripting (XSS) in an HTTP request URI"),
        Rule("HTTP_WEB_ATTACK_LFI", _WEB_ATTACK, "Cleartext", "Local file inclusion in an HTTP request URI"),
        Rule("HTTP_WEB_ATTACK_TRAVERSAL", _WEB_ATTACK, "Cleartext", "Path traversal in an HTTP request URI"),
        Rule("HTTP_WEB_ATTACK_COMMAND_INJECTION", _WEB_ATTACK, "Cleartext", "OS command injection in an HTTP request URI"),
        Rule("TLS_ECH_OFFERED", _ECH_0RTT, "Crypto", "Encrypted Client Hello (ECH) offered"),
        Rule("TLS_EARLY_DATA_OFFERED", _ECH_0RTT, "Crypto", "TLS 1.3 0-RTT early data offered"),
        Rule("VPN_IKE_HANDSHAKE", _VPN, "Network", "IKE/IPsec handshake seen (ISAKMP on UDP 500/4500)"),
        Rule("VPN_WIREGUARD_HANDSHAKE", _VPN, "Network", "WireGuard handshake seen (UDP 51820)"),
        Rule("VPN_OPENVPN_HANDSHAKE", _VPN, "Network", "OpenVPN control-channel handshake seen (UDP/TCP 1194)"),
        Rule("HTTP2_CLEARTEXT", _HTTP2, "Cleartext", "HTTP/2 over cleartext (h2c) traffic is not encrypted"),
    )
}


#: One line per category: what is at stake, for someone reading a finding (the interactive review, #98).
CATEGORY_IMPACT: dict[str, str] = {
    "Crypto": "Anyone who records this traffic can decrypt or alter it, now or later.",
    "Credentials": "Anyone on the network path can capture these credentials and reuse them.",
    "Cleartext": "Data, commands and downloads are readable and modifiable on the network path.",
    "DNS": "Lookups reveal what devices talk to, or DNS is being used to move data covertly.",
    "SSH & QUIC": "Remote access or transport security can be downgraded or attacked.",
    "Voice": "Calls and call signalling can be listened to or hijacked.",
    "Network": "The traffic shape suggests scanning, beaconing, or services exposed where they should not be.",
    "Signatures": "Traffic matched a detection rule you supplied; what is at stake is whatever that rule encodes.",
    "SMB": "Windows file sharing is exposed to relay, enumeration or remote execution from the network.",
    "Other": "A finding the rule catalog does not classify yet.",
}


def category_of(code: str) -> str:
    """User-facing category of a finding code; "Other" for a code missing from the catalog."""
    rule = RULES.get(code)
    return rule.category if rule else "Other"


#: Suricata-style classtype vocabulary (Suricata ``classification.config``), shown next to the existing
#: fields in the JSON and EVE outputs (issue #241).
CLASS_TYPES: tuple[str, ...] = (
    "attempted-recon", "trojan-activity", "policy-violation", "protocol-command-decode",
    "misc-activity", "attempted-admin",
)
DEFAULT_CLASSTYPE = "misc-activity"

#: One mapping table keyed by exact code; codes missing from it take the ``misc-activity`` default.
_CLASSTYPES: dict[str, str] = {
    "SYN_SCAN_SHAPE": "attempted-recon",
    "PORT_SCAN_VERTICAL": "attempted-recon",
    "PORT_SCAN_HORIZONTAL": "attempted-recon",
    "BEACONING_SHAPE": "trojan-activity",
    "ARP_SPOOFING_SUSPECTED": "trojan-activity",
    "ICMP_REDIRECT": "trojan-activity",
    "DNS_TUNNEL_SHAPE": "trojan-activity",
    "TLS_HEARTBLEED_PROBE": "trojan-activity",
    "DNS_CLEARTEXT": "policy-violation",
    "HTTP_MISSING_SECURITY_HEADERS": "policy-violation",
    "TLS_VERSION_DEPRECATED": "policy-violation",
    "TLS_LEGACY_RECORD_VERSION": "policy-violation",
    "TLS_CIPHER_WEAK": "policy-violation",
    "TLS_OFFERS_WEAK_CIPHERS": "policy-violation",
    "TLS_NO_FORWARD_SECRECY": "policy-violation",
    "TLS_CERT_EXPIRED": "policy-violation",
    "TLS_CERT_EXPIRED_NOW": "policy-violation",
    "TLS_CERT_EXPIRING": "policy-violation",
    "TLS_CERT_WEAK_KEY": "policy-violation",
    "TLS_CERT_WEAK_SIGALG": "policy-violation",
    "TLS_CERT_NOT_YET_VALID": "policy-violation",
    "TLS_NO_EXTENDED_MASTER_SECRET": "policy-violation",
    "TLS_NO_SCT": "policy-violation",
    "TLS_WEAK_DH_GROUP": "policy-violation",
    "TLS_COMPRESSION_ENABLED": "policy-violation",
    "TLS_INSECURE_RENEGOTIATION": "policy-violation",
    "CLEARTEXT_CREDENTIAL": "policy-violation",
    "HTTP_BASIC_AUTH": "policy-violation",
    "HTTP_CLEARTEXT_AUTH": "policy-violation",
    "HTTP_COOKIE_NO_SECURE": "policy-violation",
    "BRUTE_FORCE_SUSPECTED": "policy-violation",
    "SMB_SIGNING_NOT_REQUIRED": "policy-violation",
    "SMB_NULL_SESSION": "policy-violation",
    "SIP_CLEARTEXT_SIGNALLING": "policy-violation",
    "SDP_NO_CRYPTO_ATTR": "policy-violation",
    "RTP_MEDIA_UNPROTECTED": "policy-violation",
    "SSH_WEAK_KEX": "attempted-admin",
    "SSH_WEAK_CIPHER": "attempted-admin",
    "SSH_WEAK_MAC": "attempted-admin",
    "SSH_WEAK_HOSTKEY": "attempted-admin",
    "SMB_ADMIN_SHARE_ACCESS": "attempted-admin",
    "SMB_REMOTE_EXEC_PIPE": "attempted-admin",
    "SIGNATURE_MATCH": "attempted-admin",
    "HTTP_WEB_ATTACK_SQLI": "attempted-admin",
    "HTTP_WEB_ATTACK_XSS": "attempted-admin",
    "HTTP_WEB_ATTACK_LFI": "attempted-admin",
    "HTTP_WEB_ATTACK_TRAVERSAL": "attempted-admin",
    "HTTP_WEB_ATTACK_COMMAND_INJECTION": "attempted-admin",
    "TLS_SELF_SIGNED_CHAIN": "protocol-command-decode",
    "TLS_SNI_CERT_MISMATCH": "protocol-command-decode",
    "SMB1_IN_USE": "protocol-command-decode",
    "SMB_EXECUTABLE_ON_SHARE": "protocol-command-decode",
}


def classtype_of(code: str) -> str:
    """Suricata-style classtype of a finding code; ``misc-activity`` for a code without a mapping."""
    return _CLASSTYPES.get(code, DEFAULT_CLASSTYPE)
