# KERBEROS_NO_PREAUTH

## What it means
The KDC answered an AS request that carried no PA-ENC-TIMESTAMP, and it never sent KDC_ERR_PREAUTH_REQUIRED for that exchange. The account has Kerberos pre-authentication turned off ("do not require Kerberos preauthentication").

## Why it matters
Without pre-authentication any host on the network can request an AS reply for that account and crack the returned material offline (AS-REP roasting). No password is needed to start the attack.

## How to fix
- Clear "Do not require Kerberos preauthentication" on the account (`Set-ADAccountControl -DoesNotRequirePreAuth $false`), unless a documented application requires it.
- Reset the account password, since any reply already captured may have been cracked.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; KERBEROS_NO_PREAUTH must no longer be reported for that principal.
