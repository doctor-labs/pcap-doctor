# KERBEROS_TGS_WITHOUT_AS

## What it means
The KDC issued a service ticket to a principal, but no AS request or AS reply for that principal appears anywhere in the capture. The finding names the principal and the service, and points at the frame that carried the ticket.

## Why it matters
A service ticket is normally the second half of an authentication: the client proves who it is with an AS exchange, and the KDC hands out a ticket-granting ticket that it then exchanges for service tickets. A service ticket with no AS exchange behind it means one of three things:
- the capture starts after the authentication, so the AS exchange is simply off-screen;
- the ticket came from delegation (S4U2Self, or constrained delegation to another service), so the client proved who it is to a different service than the one it is now using;
- the ticket was obtained elsewhere and replayed here.

Only the capture can tell which, so the finding is reported with low confidence. It matters because delegation and ticket replay are both ways a compromised credential reaches services it was never meant to reach, and because a domain client that authenticates once and then holds service tickets for hours is worth knowing about.

## How to fix
- Check whether the AS exchange happened before the start of the capture. If it did, this is capture-window noise and no action is needed.
- If it did not, review S4U2Self and constrained delegation on the account and on the KDC: `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` are the attributes that carry the risk.
- Confirm the address that requested the ticket is the host you expect for that principal.

## How to verify
Capture from before the client authenticates, so the AS exchange is inside the capture window, and run `pcap-doctor analyze <capture>`; KERBEROS_TGS_WITHOUT_AS must no longer be reported for that principal and service. If it is still reported, the ticket genuinely is not backed by an AS exchange in view.
