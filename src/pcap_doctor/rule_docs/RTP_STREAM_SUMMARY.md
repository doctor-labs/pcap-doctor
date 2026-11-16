# RTP_STREAM_SUMMARY

## What it means
An RTP media stream was observed and summarised with its source and destination, payload type, duration, packet and byte counts, sequence-gap loss, interarrival jitter and an estimated MOS (ITU-T G.107) band.

## Why it matters
Analysts need a quick, playable description of each stream to follow a call and correlate it with signalling, endpoints and any quality problems.

## How to fix
- No action required; this is an informational summary of the stream.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; the stream summary will reflect the observed packets and timing.
