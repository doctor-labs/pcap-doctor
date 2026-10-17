# SERVICE_VULNERABLE_VERSION

## What it means
A host announced a specific software version in a cleartext banner or header (HTTP `Server`, HTTP `User-Agent`, or an SSH identification string), and that version falls in a range with a published vulnerability. The finding names the host, the software, the version and the CVE.

## Why it matters
Banners are often the only inventory an observer gets. A version inside a known-vulnerable range is a likely defect, which is why the severity is medium. The match is still a heuristic: the version is self-reported, a vendor may have backported a fix, and this capture does not prove the service is reachable or exploitable. Confidence is therefore medium.

## How to fix
- Upgrade the named software to a release outside the affected range listed in the CVE.
- If the build is a vendor package, confirm with the vendor that the installed version carries the backported fix.
- Reduce the banner where the product allows it (for example `ServerTokens Prod` for Apache, `DebianBanner no` for OpenSSH) so the version is not announced to every peer.
- Keep the service off untrusted networks until it is updated.

## How to verify
Re-capture the same traffic after the upgrade and run `pcap-doctor analyze <capture>`. `SERVICE_VULNERABLE_VERSION` must no longer be reported for that host and software, and must be absent for any version outside the listed ranges.
