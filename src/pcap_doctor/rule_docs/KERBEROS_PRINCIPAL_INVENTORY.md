# KERBEROS_PRINCIPAL_INVENTORY

## What it means
A Kerberos reply shows which principal authenticated to which realm and which service ticket it received: `principal@REALM` obtained a ticket for `krbtgt/REALM` (a ticket-granting ticket) or for a service such as `cifs/fileserver.example`. The finding names the principal, the realm and the service, and points at the frame that carried them. It is inventory, not a defect.

## Why it matters
A capture is a list of conversations until you know which accounts are speaking. This is the mapping an analyst needs before anything else: it tells you which hosts on the network hold domain credentials, which realm trusts which other, and which services those credentials reach. It also gives you the baseline to compare a later capture against.

## How to fix
No action is required for the inventory entry itself. Two things are worth doing with it:
- Confirm each principal is expected to use that service, and that the account is neither shared nor generic. A principal using a service nobody expected is either a misconfiguration or a host you do not control.
- Keep the mapping as an asset record. When a finding names a principal (a weak ticket, a ticket without an AS exchange, an anonymous reply), this is the list you need to act on it.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; the principal, realm and service for the exchange must still be listed. If a principal disappears from the inventory, the client no longer authenticates that way.
