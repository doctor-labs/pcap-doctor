# SERVICE_FINGER_EXPOSED

## What it means
Traffic involving the Finger service (TCP/79) was observed, indicating an exposed user-information service.

## Why it matters
Finger discloses account and user details by design and has historically been abused for reconnaissance.

## How to fix
- Disable Finger or strictly restrict access to trusted networks.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_FINGER_EXPOSED must be absent once the service is removed or blocked.
