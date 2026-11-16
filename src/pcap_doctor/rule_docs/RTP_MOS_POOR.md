# RTP_MOS_POOR

## What it means
The stream's estimated Mean Opinion Score is below 3.6 (poor or bad band), derived from measured packet loss using the ITU-T G.107 E-model as implemented by the core `estimate_mos` helper.

## Why it matters
An MOS under 3.6 predicts noticeably impaired or unsatisfactory perceived voice quality for listeners on that stream.

## How to fix
- Address the underlying packet loss and delay variation on the media path; lowering loss raises the estimated MOS.
- Re-test after network changes to confirm the score returns to the fair/good range (3.6 or above).

## How to verify
Capture the affected call again and run `pcap-doctor analyze <capture>`; RTP_MOS_POOR must not be reported when the estimated MOS is 3.6 or higher.
