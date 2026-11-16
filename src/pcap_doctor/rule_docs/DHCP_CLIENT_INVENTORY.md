# DHCP_CLIENT_INVENTORY

## What it means
A host took part in a DHCP exchange: the finding names its hardware address, the host name it asked for, the address it was offered and the length of the lease.

## Why it matters
DHCP is the first thing a machine says on a network, and it says it in the clear. The hardware address, the name and the lease tell a listener exactly who is present, what it is called and how long it will stay. That is the inventory an attacker wants before choosing a target, and it is the inventory you want for asset management.

## How to fix
Inventory only, no fix required. Two things are worth doing with it:
- Record the host, and check that the name matches what the asset register says. A name that does not match is either an unmanaged device or something that renamed itself to look like a machine you own.
- If the device does not need a lease at all, give it a static address or move it to a segment where the announcement does not matter.

## How to verify
Capture the same segment again and run `pcap-doctor analyze <capture>`; the host must still be listed with the same hardware address. If a host disappears from the inventory it stopped using DHCP, which is worth knowing.
