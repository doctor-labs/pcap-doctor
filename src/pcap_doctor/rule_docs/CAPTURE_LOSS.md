# CAPTURE_LOSS

## What it means
More than 10% of the TCP ACKs in the capture are matched by segments that arrive after a hole in their own stream (tshark's `tcp.analysis.lost_segment`: data was captured on both sides of the hole). ACKs of data never captured at all are not counted, since every capture that starts mid-connection has them. This mirrors, Zeek's `capture_loss.log` `Too_Much_Loss`. The capture dropped packets or was taken on the wrong side of a SPAN/tap, so the byte stream the analysis reconstructs is incomplete.

## Why it matters
Capture loss hides the very data an analyst is trying to read: reassembled streams are missing bytes, signatures miss matches, and findings based on that traffic understate what happened. A flow that looks like a clean request may in fact span several lost segments, so any finding derived from it needs corroboration from another sensor.

## How to fix
- Capture closer to the hosts (or the destination that ACKs the missing data).
- Raise the capture buffer (`buffer/snaplen` on the capture interface) and the kernel ring buffer, e.g. `sysctl -w net.core.rmem_max`.
- Check the tap/SPAN for drops, oversubscription, or sampling; confirm the port mirroring ingress/egress direction.
- For long-running captures, prefer ring-buffered capture to RAM-backed files.

## How to verify
Capture the same traffic again and run `pcap-doctor logs CAPTURE --only capture_loss`; `percent_lost` must drop below 10% and `CAPTURE_LOSS` must no longer be reported.
