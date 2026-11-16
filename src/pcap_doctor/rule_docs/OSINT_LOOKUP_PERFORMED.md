# OSINT_LOOKUP_PERFORMED

## What it means
An indicator from this capture (such as the capture's SHA-256, or a hostname or domain seen in it) was sent to an OSINT lookup endpoint because the operator explicitly requested it with `pcap-doctor osint --endpoint`. The finding records which indicator was looked up, which endpoint was contacted, and the result that endpoint returned.

## Why it matters
External reputation or enrichment services can add context to indicators observed in a capture. Because the query leaves the machine and is shared with that endpoint, it runs only when the operator opts in.

## How to fix
No fix is required for the capture itself. Review the returned result as one data point and confirm it with other evidence before acting on it.

## How to verify
Run `pcap-doctor osint <capture>` without `--endpoint` to confirm no external lookup is performed. Run it with `--endpoint <url>` only when you intend to query that service, and confirm the output states that the query left the machine and reports the returned result.
