# D15 -- cleartext ICS write and control commands (#206). Flags Modbus write function codes (requests to port 502),
# DNP3 write, select, operate and restart function codes, S7comm Write Var (ROSCTR Job), and IEC 60870-5-104
# activation (cause 6) of command ASDU types 45 to 51. Replies are never flagged: the codes below are request codes.
# All four protocols are read from one batched tshark pass (ics_control), so analyze launches one extra pass.

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from ..index import CaptureIndex, first
from ..models import Finding
from ..tshark import Row, to_int, to_int_auto
from .base import Detector, ev

_LABEL = {"modbus": "Modbus", "dnp3": "DNP3", "s7comm": "S7comm", "iec104": "IEC 60870-5-104"}
_MODBUS_WRITES = {5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER", 15: "WRITE_MULTIPLE_COILS",
                  16: "WRITE_MULTIPLE_REGISTERS", 22: "MASK_WRITE_REGISTER", 23: "READ_WRITE_MULTIPLE_REGISTERS"}
_DNP3_CONTROLS = {2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR",
                  13: "COLD_RESTART", 14: "WARM_RESTART"}
_S7_JOB = 1
_S7_WRITE_VAR = 5
_IEC104_ACTIVATION = 6
_IEC104_COMMANDS = {45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1", 49: "C_SE_NB_1",
                    50: "C_SE_NC_1", 51: "C_BO_NA_1"}

# protocol token, source, destination, destination port, frame number, command name
Hit = tuple[str, str, str, int, int, str]


def _port(row: Row) -> int | None:
    return to_int(first(row, "tcp.dstport")) or to_int(first(row, "udp.dstport"))


def _hit(proto: str, row: Row, port: int | None, name: str) -> Hit | None:
    src = first(row, "ip.src") or first(row, "ipv6.src")
    dst = first(row, "ip.dst") or first(row, "ipv6.dst")
    frame = to_int(first(row, "frame.number")) or 0
    if not src or not dst or port is None or frame <= 0:
        return None
    return (proto, src, dst, port, frame, name)


def _commands(index: CaptureIndex) -> list[Hit]:
    runner = index.runner
    if runner is None:  # a hand-built index has no tshark passes to read
        return []
    found: list[Hit | None] = []
    for row in runner.run("ics_control"):
        port = _port(row)
        if first(row, "modbus.func_code"):
            name = _MODBUS_WRITES.get(to_int(first(row, "modbus.func_code")) or -1)
            if name and port == 502:  # requests go to the server port; replies come back from it
                found.append(_hit("modbus", row, port, name))
        if first(row, "dnp3.al.func"):
            name = _DNP3_CONTROLS.get(to_int(first(row, "dnp3.al.func")) or -1)
            if name:
                found.append(_hit("dnp3", row, port, name))
        if to_int(first(row, "s7comm.header.rosctr")) == _S7_JOB and to_int_auto(first(row, "s7comm.param.func")) == _S7_WRITE_VAR:
            found.append(_hit("s7comm", row, port, "Write Var"))
        if first(row, "iec60870_asdu.typeid"):
            name = _IEC104_COMMANDS.get(to_int(first(row, "iec60870_asdu.typeid")) or -1)
            if name and to_int(first(row, "iec60870_asdu.causetx")) == _IEC104_ACTIVATION:
                found.append(_hit("iec104", row, port, name))
    return [hit for hit in found if hit is not None]


class IcsControl(Detector):
    name: ClassVar[str] = "d20.ics_control"
    title: ClassVar[str] = "Cleartext ICS write or control command"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "protocol"
    description: ClassVar[str] = "Write, select, operate and restart commands on Modbus, DNP3, S7comm and IEC 60870-5-104 seen in cleartext (#206)."

    def detect(self, index: CaptureIndex) -> list[Finding]:
        groups: dict[tuple[str, str, str, int], list[Hit]] = defaultdict(list)
        for hit in _commands(index):
            groups[(hit[0], hit[1], hit[2], hit[3])].append(hit)
        findings: list[Finding] = []
        for (proto, src, dst, port), group in sorted(groups.items()):
            label = _LABEL[proto]
            names = sorted({hit[5] for hit in group})
            listed = ", ".join(names)
            findings.append(
                self.finding(
                    code="ICS_CONTROL_COMMAND",
                    title=f"{label} write or control command in cleartext",
                    severity="medium",
                    confidence="high",
                    summary=(f"{src} sent {len(group)} {label} write or control command(s) to {dst}:{port} "
                             f"({listed}) in cleartext; the capture shows no authentication step for them."),
                    scope=f"{proto}|{src}>{dst}:{port}",
                    subjects=[src, f"{dst}:{port}"],
                    evidence=[ev(hit[4], f"{proto}.command", hit[5]) for hit in group[:5]],
                    remediation=("Confirm each command was intended and authorized. Restrict these function codes to engineering "
                                 "stations by source address, and where the device supports it use the authenticated variant "
                                 "(DNP3 Secure Authentication, IEC 62351)."),
                    references=["CWE-306"],
                    tags=["ics", proto],
                )
            )
        return findings
