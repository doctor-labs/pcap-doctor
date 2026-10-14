# IOC_MATCH

## What it means
An IP address, domain or URL seen in this capture matches an indicator from a file you supplied with `--ioc`. The finding names the indicator, the subject as it appeared (IP, name, or host and URI), the source (DNS answer, TLS SNI, HTTP request or observed host) and the frame where it appeared.

## Why it matters
The indicator came from a source you chose to trust, such as a threat feed or an incident note. A match means that host or name was contacted or resolved in this capture. It is evidence of contact, not proof of compromise.

## How to fix
- Check the indicator's age and source: stale or mislabelled entries produce false positives.
- Investigate the flow and host cited in the finding, and isolate the host if the contact is unexpected.
- Remove the indicator from the file if it does not apply to this network.

## How to verify
Re-run `pcap-doctor analyze <capture> --ioc <file>` after the change. The `IOC_MATCH` finding for that indicator must no longer appear.
