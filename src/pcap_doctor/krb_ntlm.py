"""Kerberos and NTLMSSP message metadata from the ``kerberos`` and ``ntlm`` tshark passes (#205).

Message types, realms, principals, encryption types, pre-authentication presence, NTLM message types, negotiated
flags and security-buffer lengths. Never a ticket, a key, a challenge response or any other ciphertext.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .tshark import Row, to_int

KRB_AS_REQ, KRB_AS_REP, KRB_TGS_REQ, KRB_TGS_REP, KRB_ERROR = 10, 11, 12, 13, 30
#: KDC_ERR_PREAUTH_REQUIRED: the KDC asked the client for pre-authentication
KDC_ERR_PREAUTH_REQUIRED = 25
#: PA-ENC-TIMESTAMP, the pre-authentication a client sends with an AS-REQ
PA_ENC_TIMESTAMP = 2
#: Deprecated encryption types (RFC 6649): DES and RC4-HMAC
WEAK_ETYPES = {1: "des-cbc-crc", 3: "des-cbc-md5", 23: "rc4-hmac", 24: "rc4-hmac-exp"}
DES_ETYPES = {1, 3}
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_CHALLENGE, NTLMSSP_AUTHENTICATE = 2, 3
#: an NTLMv1 LM or NT response is 24 bytes; every NTLMv2 NT response is longer
NTLMV1_RESPONSE_LEN = 24


class KrbMsg(BaseModel):
    key: str
    frame: int
    msg_type: int
    realm: str | None = None
    client: str | None = None
    service: str | None = None
    etypes: list[int] = Field(default_factory=list)
    padata: list[int] = Field(default_factory=list)  # pre-authentication data types present in the message
    error: int | None = None


class NtlmMsg(BaseModel):
    key: str
    frame: int
    message_type: int  # 1 NEGOTIATE, 2 CHALLENGE, 3 AUTHENTICATE
    flags: int | None = None  # NTLMSSP negotiate flags
    nt_len: int | None = None  # NT response length in an AUTHENTICATE (blobs come LM, then NT); lengths only
    username: str | None = None
    domain: str | None = None


def parse_kerberos(rows: list[Row], key_of: object) -> list[KrbMsg]:  # key_of: Callable[[Row], str | None]
    from .index import first, many

    out: list[KrbMsg] = []
    for row in rows:
        key = key_of(row)  # type: ignore[operator]
        msg = to_int(first(row, "kerberos.msg_type"))
        if not key or msg is None:
            continue
        realm = first(row, "kerberos.crealm") or first(row, "kerberos.realm") or None
        cname = first(row, "kerberos.CNameString") or None
        out.append(KrbMsg(
            key=key, frame=to_int(first(row, "frame.number")) or 0, msg_type=msg, realm=realm,
            client=f"{cname}@{realm}" if cname and realm else cname,
            service="/".join(many(row, "kerberos.SNameString")) or None,
            etypes=[e for e in (to_int(v) for v in many(row, "kerberos.etype")) if e is not None],
            padata=[p for p in (to_int(v) for v in many(row, "kerberos.padata_type")) if p is not None],
            error=to_int(first(row, "kerberos.error_code")),
        ))
    return out


def parse_ntlm(rows: list[Row], key_of: object) -> list[NtlmMsg]:  # key_of: Callable[[Row], str | None]
    from .index import first, many

    out: list[NtlmMsg] = []
    for row in rows:
        key = key_of(row)  # type: ignore[operator]
        if not key:
            continue
        types = [t for t in (to_int(v, 16) for v in many(row, "ntlmssp.messagetype")) if t is not None]
        flags = to_int(first(row, "ntlmssp.negotiateflags"), 16)
        blobs = [b for b in (to_int(v) for v in many(row, "ntlmssp.blob.length")) if b is not None]
        for message_type in types:
            out.append(NtlmMsg(
                key=key, frame=to_int(first(row, "frame.number")) or 0, message_type=message_type, flags=flags,
                nt_len=blobs[1] if len(blobs) >= 2 and message_type == NTLMSSP_AUTHENTICATE else None,
                username=first(row, "ntlmssp.auth.username") or None,
                domain=first(row, "ntlmssp.auth.domain") or None,
            ))
    return out
