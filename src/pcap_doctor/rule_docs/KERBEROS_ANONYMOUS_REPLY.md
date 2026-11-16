# KERBEROS_ANONYMOUS_REPLY

## What it means
A Kerberos reply carries a realm but no client principal: the KDC answered a request that named nobody and issued a ticket that names nobody. The finding names the realm and points at the frame.

## Why it matters
Anonymous PKINIT lets a client obtain a Kerberos ticket without proving who it is. The ticket then names no principal, so every audit that maps a ticket back to an account sees nothing: the activity is present in the capture and unattributable. Where anonymous PKINIT is enabled, the realm is an unauthenticated entry point for anything that can reach the KDC, and services that trust the realm will accept it.

## How to fix
- Turn anonymous PKINIT off for the realm. On Active Directory this is the KDC policy under "Network security: Configurable encryption types" (clear "Enable Kerberos Authentication using PKINIT" for the anonymous option) and the matching registry setting on the domain controllers.
- Require pre-authentication on the affected accounts, so that even an anonymous request cannot obtain a usable ticket.
- Review the KDC log for anonymous requests over the period the capture covers; each one is a client that asked for a ticket and did not want to be named.

## How to verify
Re-run the same request against the KDC and capture it, then run `pcap-doctor analyze <capture>`; KERBEROS_ANONYMOUS_REPLY must no longer be reported, and the KDC log must show the request refused.
