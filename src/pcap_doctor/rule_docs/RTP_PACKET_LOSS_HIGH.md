# RTP_PACKET_LOSS_HIGH

## What it means
The RTP stream shows packet loss at or above 1% of expected packets, measured from sequence-number gaps (RFC 3550) and reported as a percentage with the gap count.

## Why it matters
Lost packets cannot be fully concealed; sustained loss causes clipping, robotic audio and dropped words, and degrades the estimated call quality.

## How to fix
- Investigate congestion, queue drops, Wi-Fi contention or capture loss on the media path.
- Prioritise voice traffic (QoS/DSCP) and repair links that drop packets until loss stays below 1%.

## How to verify
Capture the affected call again and run `pcap-doctor analyze <capture>`; RTP_PACKET_LOSS_HIGH must not be reported when loss is below the threshold.
