# RTP_JITTER_HIGH

## What it means
The RTP stream's interarrival jitter is at or above 30 ms, computed with the RFC 3550 Appendix A.8 estimator from packet timestamps and arrival times.

## Why it matters
High jitter exhausts the receiver's dejitter buffer, leading to late or discarded packets that sound like choppy, uneven or clipped audio even when packets are not lost.

## How to fix
- Reduce variable queuing delay and contention on the path (QoS, less competing traffic, stable wireless).
- Keep interarrival jitter comfortably below 30 ms so the jitter buffer can absorb variation.

## How to verify
Capture the affected call again and run `pcap-doctor analyze <capture>`; RTP_JITTER_HIGH must not be reported when jitter is below the threshold.
