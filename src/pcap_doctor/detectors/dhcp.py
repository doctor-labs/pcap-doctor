"""D26 -- DHCP and DHCPv6: host inventory, rogue servers, and what the exchange leaks.

DHCP is the first thing a host says on a network, in the clear: its hardware address, the name it
was given, the domain it belongs to and the model of the device. That makes it both a host
inventory source and a small information leak, and it makes it the place a rogue server shows up.

The detector reads the ``dhcp`` and ``dhcpv6`` tshark passes on demand. Only what the capture
shows is reported: an identity that was sent, a server that answered, a name that was broadcast.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, flow_key
from ..tshark import Row, to_int
from .base import Detector, ev

RFC_2131 = "RFC 2131"
RFC8415 = "RFC 8415"
CWE_200 = "CWE-200"


def _flow_of(row: Row) -> str:
    """The flow key of the exchange a row belongs to, or an empty string."""
    # An IPv6 exchange carries the addresses in the ipv6.* columns, not ip.*.
    src = _first(row, "ip.src") or _first(row, "ipv6.src")
    dst = _first(row, "ip.dst") or _first(row, "ipv6.dst")
    sport, dport = to_int(_first(row, "udp.srcport")), to_int(_first(row, "udp.dstport"))
    if not src or not dst or sport is None or dport is None:
        return ""
    return flow_key("udp", src, sport, dst, dport)


def _first(row: Row, field: str) -> str:
    """The first value of a tshark field, or an empty string."""
    values = row.get(field) or []
    return values[0] if values else ""


class DhcpDetector(Detector):
    name: ClassVar[str] = "d26.dhcp"
    title: ClassVar[str] = "DHCP host inventory and server behaviour"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = (
        "Which host asked for an address and what it told the network about itself, DHCP servers that "
        "answer the same request with different parameters, and the domain and vendor information "
        "broadcast in the clear."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:  # a hand-built index has no tshark passes to read
            return []
        out: list[Finding] = []
        try:
            rows = runner.run("dhcp")
        except KeyError:  # the pass is not registered in this build
            return []
        out.extend(self._v4(index, rows))
        try:
            rows6 = runner.run("dhcpv6")
        except KeyError:
            rows6 = []
        out.extend(self._v6(index, rows6))
        return out

    # -- IPv4 ---------------------------------------------------------------

    def _v4(self, index: CaptureIndex, rows: list[Row]) -> list[Finding]:
        out: list[Finding] = []
        # xid -> the servers that answered it, with the address each one offered.
        answers: dict[str, dict[str, str]] = {}
        clients: dict[str, dict[str, str]] = {}

        for row in rows:
            xid = _first(row, "dhcp.id")
            msg = to_int(_first(row, "dhcp.option.dhcp"))
            src = _first(row, "ip.src")
            mac = _first(row, "dhcp.hw.mac_addr")
            host = _first(row, "dhcp.option.hostname")
            domain = _first(row, "dhcp.option.domain_name")
            vendor = _first(row, "dhcp.option.vendor_class_id")
            your = _first(row, "dhcp.ip.your")
            lease = to_int(_first(row, "dhcp.option.ip_address_lease_time"))
            server_id = _first(row, "dhcp.option.dhcp_server_id")
            if not xid:
                continue

            if msg in (2, 5):  # OFFER or ACK: a server answering
                who = server_id or src
                answers.setdefault(xid, {})[who] = your or server_id or src
                # The address the client ends up with is in the server's reply, not its request.
                if mac:
                    entry = clients.setdefault(mac, {})
                    if your and your != "0.0.0.0":
                        entry["ip"] = your
                    if lease:
                        entry["lease"] = str(lease)
                    entry.setdefault("flow", _flow_of(row))
                answers.setdefault(xid, {}).setdefault("flow", _flow_of(row))
                continue

            # A client request: DISCOVER (1), REQUEST (3), INFORM (8), DECLINE (4).
            if mac:
                entry = clients.setdefault(mac, {})
                entry.setdefault("name", host)
                entry.setdefault("ip", your)
                entry.setdefault("lease", str(lease))
                entry.setdefault("domain", domain)
                entry.setdefault("vendor", vendor)
                entry.setdefault("flow", _flow_of(row))

        # Two servers answering the same transaction with different addresses.
        for xid, servers in answers.items():
            if len(servers) < 2:
                continue
            addresses = set(servers.values())
            if len(addresses) < 2:
                continue
            who = sorted(servers)[0]
            out.append(self.finding(
                code="DHCP_ROGUE_SERVER",
                title=f"DHCP transaction {xid} answered by {len(servers)} servers",
                severity="high", confidence="high",
                summary=f"Two or more DHCP servers answered the same transaction ({xid}) with different addresses: "
                f"{', '.join(sorted(servers))}. The client accepts whichever it hears first, so a host on the "
                "network can hand out an address, a gateway or a DNS server of its choosing.",
                scope=f"rogue-server|{xid}", flow_key=answers[xid].get("flow") or None,
                subjects=sorted(servers),
                evidence=[ev(self._frame_of(rows), "dhcp.id", xid)],
                remediation="Point the network at one DHCP server: disable the rogue service or its relay, and "
                "filter DHCP server traffic (UDP port 67) to the authorised server on the edge.",
                references=[RFC_2131], tags=["dhcp", "rogue-server"]))

        for mac, info in clients.items():
            name = info.get("name") or ""
            address = info.get("ip") or ""
            lease_text = info.get("lease") or ""
            scope = f"client|{mac}"
            out.append(self.finding(
                code="DHCP_CLIENT_INVENTORY",
                title=f"DHCP client {mac}" + (f" ({name})" if name else ""),
                severity="info", confidence="high",
                summary=f"Host {mac}" + (f" asked for the name '{name}'" if name else "") +
                (f", was offered {address}" if address else "") +
                (f" with a {lease_text} second lease" if lease_text else "") +
                ". DHCP announces the hardware address, the name and the lease in the clear, so any listener "
                "on the segment learns who is there.",
                scope=scope, flow_key=info.get("flow") or None,
                evidence=[ev(self._frame_of(rows), "dhcp.hw.mac_addr", mac)],
                remediation="Inventory only: record the host. If the device does not need a lease (a phone on "
                "a guest network, a static host), give it a static address or keep it off the segment.",
                references=[RFC_2131, CWE_200], tags=["dhcp", "inventory"]))

            domain = info.get("domain") or ""
            if domain:
                out.append(self.finding(
                    code="DHCP_DOMAIN_LEAK",
                    title=f"DHCP request broadcasts the domain name {domain}",
                    severity="low", confidence="high",
                    summary=f"The client sent the domain name '{domain}' in a DHCP request, in the clear. Every "
                    "host on the segment learns the internal naming domain, which maps the network for anyone "
                    "who wants to target it.",
                    scope=f"domain|{mac}", flow_key=info.get("flow") or None,
                    evidence=[ev(self._frame_of(rows), "dhcp.option.domain_name", domain)],
                    remediation="Stop sending the domain name in DHCP (option 15) if the clients do not need it, "
                    "or move the segment to a guest VLAN.",
                    references=[RFC_2131, CWE_200], tags=["dhcp", "leak"]))

            vendor = info.get("vendor") or ""
            if vendor:
                out.append(self.finding(
                    code="DHCP_VENDOR_FINGERPRINT",
                    title=f"DHCP request advertises the vendor class {vendor}",
                    severity="info", confidence="high",
                    summary=f"The client sent the vendor class '{vendor}' in a DHCP request, in the clear. It "
                    "names the device model or the operating system, which narrows the search for whatever "
                    "weakness that model has.",
                    scope=f"vendor|{mac}", flow_key=info.get("flow") or None,
                    evidence=[ev(self._frame_of(rows), "dhcp.option.vendor_class_id", vendor)],
                    remediation="Inventory only: note the model and check it against the known issues for that "
                    "firmware. Strip the vendor class (option 60) on the edge if the segment does not need it.",
                    references=[RFC_2131, CWE_200], tags=["dhcp", "fingerprint"]))
        return out

    # -- IPv6 ---------------------------------------------------------------

    def _v6(self, index: CaptureIndex, rows: list[Row]) -> list[Finding]:
        out: list[Finding] = []
        clients: dict[str, dict[str, str]] = {}
        for row in rows:
            msg = to_int(_first(row, "dhcpv6.msgtype"))
            mac = _first(row, "dhcpv6.duidll.link_layer_addr_ether") or _first(
                row, "dhcpv6.duidllt.link_layer_addr_ether")
            address = _first(row, "dhcpv6.iaaddr.ip")
            lifetime = to_int(_first(row, "dhcpv6.iaaddr.valid_lifetime"))
            domain = _first(row, "dhcpv6.client_domain")
            vendor = _first(row, "dhcpv6.vendorclass.data")
            if not mac:
                continue
            entry = clients.setdefault(mac, {})
            entry.setdefault("ip", address)
            entry.setdefault("lease", str(lifetime))
            entry.setdefault("domain", domain)
            entry.setdefault("vendor", vendor)
            entry.setdefault("msg", str(msg))
            entry.setdefault("flow", _flow_of(row))

        for mac, info in clients.items():
            address = info.get("ip") or ""
            lease_text = info.get("lease") or ""
            out.append(self.finding(
                code="DHCPV6_CLIENT_INVENTORY",
                title=f"DHCPv6 client {mac}" + (f" ({address})" if address else ""),
                severity="info", confidence="high",
                summary=f"Host {mac} took part in a DHCPv6 exchange" +
                (f" and was given {address}" if address else "") +
                (f" with a {lease_text} second lifetime" if lease_text else "") +
                ". The DUID and the delegated address are announced in the clear.",
                scope=f"v6-client|{mac}", flow_key=info.get("flow") or None,
                evidence=[ev(self._frame_of(rows), "dhcpv6.duidll.link_layer_addr_ether", mac)],
                remediation="Inventory only: record the host. DHCPv6 is unauthenticated by design, so treat the "
                "segment as trusted and filter the relay traffic at the edge.",
                references=[RFC8415, CWE_200], tags=["dhcpv6", "inventory"]))
        return out

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _frame_of(rows: list[Row]) -> int:
        """The first frame number in the rows, as the evidence frame for a table-wide claim."""
        for row in rows:
            number = to_int(_first(row, "frame.number"))
            if number:
                return number
        return 1
