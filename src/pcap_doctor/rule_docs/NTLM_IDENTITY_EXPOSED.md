# NTLM_IDENTITY_EXPOSED

## What it means
An NTLM AUTHENTICATE message exposed the account username and domain for an exchange. The finding also reports whether the SMB session setup was accepted by the server. No response, challenge, or hash material is included.

## Why it matters
NTLM identity information reveals which accounts are authenticating over NTLM and to which peers. This can aid inventory and detection, but it also increases exposure if NTLM is used on untrusted networks.

## How to fix
- Prefer Kerberos and reduce NTLM usage, especially across network boundaries.
- Require NTLM signing and EPA/channel binding; restrict which hosts may use NTLM.
- Monitor for unexpected or privileged accounts authenticating via NTLM.

## How to verify
Capture representative traffic and confirm only expected accounts appear and NTLM exposure is minimized or eliminated according to policy.
