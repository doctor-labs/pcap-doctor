# ICS_CONTROL_COMMAND

## What it means
A host sent a write, select, operate or restart command to an industrial controller in cleartext over Modbus, DNP3, S7comm or IEC 60870-5-104. The finding is reported per source, destination and port, names the command codes seen, and lists up to five frames as evidence.

## Why it matters
The capture shows no authentication step for these commands. Anyone who can reach the controller on the network can change outputs, setpoints or device state, or restart the device. A command from an unexpected source is an operational incident until shown otherwise.

## How to fix
- Confirm each command was intended, and that its source is an authorized engineering station.
- Restrict write and control function codes by source address with firewall or industrial firewall rules.
- Where the device supports it, use the authenticated variant of the protocol: DNP3 Secure Authentication or IEC 62351.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`. ICS_CONTROL_COMMAND must be absent for the controller, or present only for a source you have confirmed.
