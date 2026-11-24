#!/usr/bin/env python3
"""
xs-ai navigator — MITRE ATT&CK Navigator layer generation.

Generates Navigator-compatible JSON layers from investigation data.
Clearly distinguishes observed, evidence-supported, AI-recommended,
and unverified techniques.  Never represents an AI recommendation
as observed adversary behavior.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Navigator layer schema (v4.5 compatible)
# ---------------------------------------------------------------------------

LAYER_VERSION = "4.5"
NAV_VERSION = "4.9.1"
DOMAIN_ENTERPRISE = "enterprise-attack"
DOMAIN_MOBILE = "mobile-attack"
DOMAIN_ICS = "ics-attack"

# Color coding by evidence level
COLORS = {
    "observed": "#c93b3b",        # red — confirmed adversary behavior
    "evidence_supported": "#e77d26",  # orange — strong evidence
    "ai_recommended": "#5c9dc4",   # blue — AI suggestion
    "unverified": "#a4a4a4",       # grey — hypothesis only
}

SCORE_MAP = {
    "observed": 100,
    "evidence_supported": 75,
    "ai_recommended": 50,
    "unverified": 25,
}


@dataclass
class TechniqueAnnotation:
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    evidence_level: str = "unverified"  # observed / evidence_supported / ai_recommended / unverified
    finding_id: str = ""
    hypothesis_id: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: str = "low"
    investigation_status: str = "pending"  # pending / in_progress / completed
    references: list[str] = field(default_factory=list)
    comment: str = ""

    def to_navigator_technique(self) -> dict:
        """Convert to ATT&CK Navigator technique entry."""
        entry: dict = {
            "techniqueID": self.technique_id,
            "color": COLORS.get(self.evidence_level, COLORS["unverified"]),
            "score": SCORE_MAP.get(self.evidence_level, 25),
            "comment": self._build_comment(),
            "enabled": True,
            "showSubtechniques": False,
            "metadata": [],
        }
        if self.tactic:
            entry["tactic"] = self.tactic
        # metadata entries
        if self.evidence_level:
            entry["metadata"].append({"name": "evidence_level", "value": self.evidence_level})
        if self.finding_id:
            entry["metadata"].append({"name": "finding_id", "value": self.finding_id})
        if self.hypothesis_id:
            entry["metadata"].append({"name": "hypothesis_id", "value": self.hypothesis_id})
        if self.confidence:
            entry["metadata"].append({"name": "confidence", "value": self.confidence})
        if self.investigation_status:
            entry["metadata"].append({"name": "investigation_status", "value": self.investigation_status})
        for ref in self.references[:5]:
            entry["metadata"].append({"name": "reference", "value": ref})
        return entry

    def _build_comment(self) -> str:
        parts = []
        if self.evidence_level == "ai_recommended":
            parts.append("[AI RECOMMENDATION — not observed behavior]")
        elif self.evidence_level == "unverified":
            parts.append("[UNVERIFIED HYPOTHESIS]")
        elif self.evidence_level == "evidence_supported":
            parts.append("[Evidence-supported]")
        elif self.evidence_level == "observed":
            parts.append("[Observed/confirmed]")
        if self.comment:
            parts.append(self.comment)
        if self.evidence:
            parts.append("Evidence: " + "; ".join(self.evidence[:3]))
        if self.finding_id:
            parts.append(f"Finding: {self.finding_id}")
        if self.hypothesis_id:
            parts.append(f"Hypothesis: {self.hypothesis_id}")
        return " | ".join(parts)


def generate_layer(name: str, description: str,
                   annotations: list[TechniqueAnnotation],
                   domain: str = DOMAIN_ENTERPRISE) -> dict:
    """Generate a complete ATT&CK Navigator layer JSON."""
    techniques = [a.to_navigator_technique() for a in annotations]

    layer = {
        "name": name,
        "versions": {
            "attack": "15",
            "navigator": NAV_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": domain,
        "description": description,
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Network",
                          "PRE", "Containers", "Office 365",
                          "SaaS", "IaaS", "Google Workspace",
                          "Azure AD"],
        },
        "sorting": 3,  # sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [COLORS["unverified"], COLORS["ai_recommended"],
                       COLORS["evidence_supported"], COLORS["observed"]],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Observed/Confirmed", "color": COLORS["observed"]},
            {"label": "Evidence-Supported", "color": COLORS["evidence_supported"]},
            {"label": "AI Recommendation", "color": COLORS["ai_recommended"]},
            {"label": "Unverified Hypothesis", "color": COLORS["unverified"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    return layer


def validate_layer(layer: dict) -> list[str]:
    """Basic validation of a Navigator layer. Returns list of issues."""
    issues = []
    if not layer.get("name"):
        issues.append("missing layer name")
    if not layer.get("domain"):
        issues.append("missing domain")
    if layer.get("domain") not in (DOMAIN_ENTERPRISE, DOMAIN_MOBILE, DOMAIN_ICS):
        issues.append(f"unknown domain: {layer.get('domain')}")
    versions = layer.get("versions", {})
    if not versions.get("layer"):
        issues.append("missing layer version")
    techs = layer.get("techniques", [])
    seen_ids = set()
    for t in techs:
        tid = t.get("techniqueID", "")
        if not tid:
            issues.append("technique entry missing techniqueID")
        if tid in seen_ids and t.get("tactic") is None:
            issues.append(f"duplicate techniqueID without tactic: {tid}")
        seen_ids.add(tid)
        if "score" in t and not isinstance(t["score"], (int, float)):
            issues.append(f"{tid}: score must be numeric")
    return issues


def save_layer(layer: dict, path: str) -> str:
    """Save layer to JSON file. Returns the path."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Conversion from xs-ai investigation data
# ---------------------------------------------------------------------------

# Common ATT&CK technique mappings for xs-ai hypothesis categories
_CATEGORY_TECHNIQUE_MAP = {
    "authentication": [("T1078", "Valid Accounts")],
    "attack-surface": [("T1190", "Exploit Public-Facing Application")],
    "configuration": [("T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "privesc": [("T1548", "Abuse Elevation Control Mechanism")],
    "technique": [("T1059", "Command and Scripting Interpreter")],
}

_PRODUCT_TECHNIQUE_MAP = {
    "splunk": [("T1059", "Command and Scripting Interpreter"),
               ("T1190", "Exploit Public-Facing Application")],
    "postgresql": [("T1059", "Command and Scripting Interpreter")],
    "manageengine": [("T1190", "Exploit Public-Facing Application")],
    "redis": [("T1557", "Adversary-in-the-Middle")],
}


def hypotheses_to_annotations(hypotheses: list[dict],
                              findings: list[str] | None = None) -> list[TechniqueAnnotation]:
    """Convert xs-ai hypotheses to Navigator annotations."""
    annotations = []
    finding_ids = set()
    if findings:
        for f in findings:
            m = __import__("re").match(r"\[([^\]]+)\]", f)
            if m:
                finding_ids.add(m.group(1))

    for h in hypotheses:
        hid = h.get("id", "")
        status = h.get("status", "")
        category = h.get("category", "")
        confidence = h.get("confidence", "low")
        service = h.get("service", "")
        obs = h.get("observation", "")

        # determine evidence level
        if status in ("confirmed",):
            evidence_level = "observed"
        elif status in ("strongly_suspected",):
            evidence_level = "evidence_supported"
        elif status in ("potential_config", "unverified"):
            evidence_level = "ai_recommended" if confidence == "low" else "unverified"
        else:
            evidence_level = "unverified"

        # find matching techniques
        techniques = _CATEGORY_TECHNIQUE_MAP.get(category, [])
        product = service.split("/")[0] if "/" in service else service
        techniques.extend(_PRODUCT_TECHNIQUE_MAP.get(product.lower(), []))

        if not techniques:
            techniques = [("T1190", "Exploit Public-Facing Application")]

        for tid, tname in techniques:
            ann = TechniqueAnnotation(
                technique_id=tid,
                technique_name=tname,
                evidence_level=evidence_level,
                hypothesis_id=hid,
                finding_id=hid if hid in finding_ids else "",
                evidence=[obs[:200]] if obs else [],
                confidence=confidence,
                investigation_status="completed" if status == "confirmed" else "pending",
                references=h.get("references", [])[:3],
                comment=obs[:100] if obs else "",
            )
            annotations.append(ann)

    return annotations


def export_investigation(target: str, hypotheses: list[dict],
                         findings: list[str] | None = None,
                         output_dir: str = "reports") -> str:
    """Export an investigation as a Navigator layer file."""
    annotations = hypotheses_to_annotations(hypotheses, findings)
    layer = generate_layer(
        name=f"xs-ai Investigation: {target}",
        description=f"ATT&CK layer generated by xs-ai for target {target}",
        annotations=annotations,
    )
    issues = validate_layer(layer)
    if issues:
        layer["_validation_issues"] = issues

    path = os.path.join(output_dir, f"navigator_{target.replace('.', '_')}.json")
    return save_layer(layer, path)
