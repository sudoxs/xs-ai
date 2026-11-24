#!/usr/bin/env python3
"""
xs-ai caldera_ot — OT-specific knowledge module (ICS/SCADA).

Separate from the enterprise Caldera adapter.  OT recommendations activate
only when relevant systems/protocols are identified or explicitly selected.
Optional module — does NOT execute tests or operations.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# ICS/OT protocol knowledge
# ---------------------------------------------------------------------------

OT_PROTOCOLS = {
    "modbus": {
        "port": 502, "name": "Modbus TCP",
        "description": "Industrial serial protocol over TCP. No built-in authentication.",
        "risks": ["No authentication by default", "Read/write coils and registers",
                   "Reconnaissance via function code scanning"],
        "attck_techniques": ["T0801", "T0831", "T0861"],
    },
    "dnp3": {
        "port": 20000, "name": "DNP3 (Distributed Network Protocol)",
        "description": "SCADA protocol for electric/water utilities.",
        "risks": ["No encryption", "Master-outstation trust model",
                   "Unsolicited response manipulation"],
        "attck_techniques": ["T0801", "T0831"],
    },
    "opc-ua": {
        "port": 4840, "name": "OPC UA",
        "description": "Industrial interoperability standard. Can have security.",
        "risks": ["Misconfigured security modes", "Anonymous access",
                   "Certificate trust issues"],
        "attck_techniques": ["T0801", "T0861"],
    },
    "bacnet": {
        "port": 47808, "name": "BACnet",
        "description": "Building automation protocol.",
        "risks": ["No authentication", "Device discovery", "Value manipulation"],
        "attck_techniques": ["T0801"],
    },
    "ethernetip": {
        "port": 44818, "name": "EtherNet/IP",
        "description": "Industrial Ethernet protocol (Allen-Bradley/Rockwell).",
        "risks": ["Implicit messaging without auth", "CIP routing abuse"],
        "attck_techniques": ["T0801", "T0831"],
    },
    "s7comm": {
        "port": 102, "name": "S7comm (Siemens S7)",
        "description": "Siemens PLC communication protocol.",
        "risks": ["No authentication on older firmware", "PLC stop/start",
                   "Memory read/write"],
        "attck_techniques": ["T0801", "T0831", "T0855"],
    },
    "iec104": {
        "port": 2404, "name": "IEC 60870-5-104",
        "description": "Power grid telecontrol protocol.",
        "risks": ["No encryption", "Command injection", "Station interrogation"],
        "attck_techniques": ["T0801", "T0831"],
    },
}

# ICS ATT&CK technique names
ICS_TECHNIQUES = {
    "T0801": "Monitor Process State",
    "T0831": "Manipulation of Control",
    "T0855": "Unauthorized Command Message",
    "T0861": "Point & Tag Identification",
    "T0821": "Modify Controller Tasking",
    "T0836": "Modify Parameter",
    "T0843": "Program Download",
    "T0886": "Remote Services",
    "T0862": "Supply Chain Compromise",
    "T0859": "Valid Accounts",
}


@dataclass
class OTFinding:
    protocol: str
    port: int
    description: str
    risks: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "port": self.port,
            "description": self.description,
            "risks": self.risks,
            "techniques": self.techniques,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
        }


def detect_ot_protocols(ports: list[int] | list[str]) -> list[OTFinding]:
    """Check if any discovered ports match known OT protocols."""
    findings = []
    port_set = {int(p) for p in ports}
    for proto_key, proto in OT_PROTOCOLS.items():
        if proto["port"] in port_set:
            findings.append(OTFinding(
                protocol=proto["name"],
                port=proto["port"],
                description=proto["description"],
                risks=proto["risks"],
                techniques=proto["attck_techniques"],
                evidence=[f"Port {proto['port']} open (matches {proto['name']})"],
                recommendations=[
                    f"Verify this is an authorized {proto['name']} service",
                    "Do NOT send commands without explicit OT operator authorization",
                    "Check network segmentation and access controls",
                ],
            ))
    return findings


def format_ot_context(findings: list[OTFinding]) -> str:
    if not findings:
        return ""
    lines = ["--- OT/ICS Protocol Detection ---",
             "WARNING: OT systems require extreme caution. Do NOT send commands."]
    for f in findings:
        lines.append(f"\n  [{f.protocol}] port {f.port}")
        lines.append(f"  {f.description}")
        lines.append(f"  Risks: {', '.join(f.risks[:3])}")
        techs = [f"{t}: {ICS_TECHNIQUES.get(t, t)}" for t in f.techniques]
        lines.append(f"  ICS ATT&CK: {', '.join(techs)}")
    return "\n".join(lines)


@dataclass
class OTKnowledge:
    findings: list[OTFinding] = field(default_factory=list)
    enabled: bool = False

    def scan_ports(self, ports: list) -> list[OTFinding]:
        self.findings = detect_ot_protocols(ports)
        if self.findings:
            self.enabled = True
        return self.findings

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "findings": [f.to_dict() for f in self.findings],
        }

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
