#!/usr/bin/env python3
"""
xs-ai research engine — turn a discovered service into evidence-based,
testable vulnerability hypotheses instead of jumping to generic enumeration.

Design goals:
- Pure standard library. No third-party dependencies.
- Works fully OFFLINE from a local knowledge base; external sources (e.g. NVD)
  are best-effort and only used when --online is set and reachable.
- Modular, pluggable research sources and per-service knowledge modules.
- Strict epistemics: confidence and severity are SEPARATE fields, and a CVE
  that merely mentions the same product is NEVER reported as confirmed.

This module is imported by client.py; it has no hard dependency on it.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Taxonomy — kept as plain constants so records serialize cleanly to JSON
# ---------------------------------------------------------------------------

# Validation status of a hypothesis (what we actually know)
STATUS_CONFIRMED = "confirmed"                 # demonstrated on this target
STATUS_SUSPECTED = "strongly_suspected"        # strong evidence, not demonstrated
STATUS_POTENTIAL_CONFIG = "potential_config"   # a configuration that may be insecure
STATUS_UNVERIFIED = "unverified"               # a hypothesis with weak evidence
STATUS_NOT_APPLICABLE = "not_applicable"       # ruled out (e.g. version mismatch)

STATUS_ORDER = {
    STATUS_CONFIRMED: 4, STATUS_SUSPECTED: 3,
    STATUS_POTENTIAL_CONFIG: 2, STATUS_UNVERIFIED: 1, STATUS_NOT_APPLICABLE: 0,
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Service fingerprint
# ---------------------------------------------------------------------------

@dataclass
class ServiceFingerprint:
    port: str
    proto: str = "tcp"
    service: str = ""          # e.g. "http", "ssh"
    product: str = ""          # e.g. "Apache httpd", "OpenSSH"
    version: str = ""          # e.g. "2.4.49"
    banner: str = ""           # raw service/version line
    # how reliable the identification is: "confirmed" (-sV/script), "inferred"
    # (port default), or "guessed"
    reliability: str = "inferred"

    def label(self) -> str:
        bits = [self.service or f"port {self.port}"]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits)

    def to_dict(self) -> dict:
        return {
            "port": self.port, "proto": self.proto, "service": self.service,
            "product": self.product, "version": self.version,
            "banner": self.banner, "reliability": self.reliability,
        }


# Parse an nmap -sV line like "8080/tcp open  http    Apache httpd 2.4.49"
_NMAP_SVC_RE = re.compile(
    r"^\s*(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<rest>.*))?$"
)


def parse_fingerprints(nmap_output: str) -> list[ServiceFingerprint]:
    """Extract service fingerprints from nmap -sV style output."""
    fps: list[ServiceFingerprint] = []
    for line in nmap_output.splitlines():
        m = _NMAP_SVC_RE.match(line)
        if not m:
            continue
        rest = (m.group("rest") or "").strip()
        product, version = "", ""
        if rest:
            # last whitespace-separated token that looks like a version
            vm = re.search(r"(\d+(?:\.\d+){1,3}[a-z]?)", rest)
            if vm:
                version = vm.group(1)
                product = rest[:vm.start()].strip()
            else:
                product = rest
        fps.append(ServiceFingerprint(
            port=m.group("port"), proto=m.group("proto"),
            service=m.group("service"), product=product, version=version,
            banner=line.strip(),
            reliability="confirmed" if rest else "inferred",
        ))
    return fps


def fingerprint_for_port(port: str, nmap_output: str = "",
                         default_service: str = "") -> ServiceFingerprint:
    """Best fingerprint for a single port from existing scan output, or a
    minimal inferred one when nothing is known yet."""
    for fp in parse_fingerprints(nmap_output):
        if fp.port == str(port):
            return fp
    return ServiceFingerprint(port=str(port), service=default_service,
                              reliability="guessed" if not default_service else "inferred")


# ---------------------------------------------------------------------------
# Version comparison + CVE applicability
#
# The spec is emphatic: never claim a vulnerability just because a CVE mentions
# the same product. We compare the detected version against affected ranges and
# downgrade confidence when the version is unknown or the issue is config-gated.
# ---------------------------------------------------------------------------

def _ver_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else ()


def version_in_range(version: str, start: str = "", end_excl: str = "",
                     end_incl: str = "") -> bool:
    """Is `version` within [start, end)? Empty bounds are open."""
    v = _ver_tuple(version)
    if not v:
        return False
    if start and v < _ver_tuple(start):
        return False
    if end_excl and not (v < _ver_tuple(end_excl)):
        return False
    if end_incl and not (v <= _ver_tuple(end_incl)):
        return False
    return True


def assess_cve_applicability(fp: ServiceFingerprint, affected: dict) -> tuple[str, str, str]:
    """Decide how a CVE applies to the observed service.

    `affected` may carry: version_start, version_end_excluding,
    version_end_including, config_gated (bool).
    Returns (status, confidence, rationale) — never 'confirmed' from version
    alone; validation is required to confirm."""
    if not fp.version:
        return (STATUS_UNVERIFIED, "low",
                "service version unknown — cannot confirm the CVE applies")
    in_range = version_in_range(
        fp.version,
        affected.get("version_start", ""),
        affected.get("version_end_excluding", ""),
        affected.get("version_end_including", ""),
    )
    has_range = any(affected.get(k) for k in
                    ("version_start", "version_end_excluding", "version_end_including"))
    if has_range and not in_range:
        return (STATUS_NOT_APPLICABLE, "high",
                f"detected {fp.version} is outside the affected range")
    if affected.get("config_gated"):
        return (STATUS_POTENTIAL_CONFIG, "medium",
                "version matches but exploitation depends on configuration — validate")
    if has_range and in_range:
        return (STATUS_SUSPECTED, "medium",
                f"detected {fp.version} is within the affected range — validate to confirm")
    return (STATUS_UNVERIFIED, "low",
            "product matches but no version range to compare — treat as unverified")


# ---------------------------------------------------------------------------
# Hypothesis record
# ---------------------------------------------------------------------------

@dataclass
class Hypothesis:
    id: str
    asset: str                 # target IP/host
    service: str               # service label
    observation: str           # what we saw that prompts this
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    validation_plan: str = ""
    severity: str = "info"     # critical/high/medium/low/info  (impact IF true)
    confidence: str = "low"    # high/medium/low                (how sure we are)
    status: str = STATUS_UNVERIFIED
    conclusion: str = ""
    category: str = ""         # authentication / configuration / cve / attack-surface
    created_at: str = field(default_factory=_now)

    def rank_key(self) -> tuple:
        return (
            STATUS_ORDER.get(self.status, 0),
            SEVERITY_ORDER.get(self.severity, 0),
            CONFIDENCE_ORDER.get(self.confidence, 0),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "asset": self.asset, "service": self.service,
            "observation": self.observation, "evidence": self.evidence,
            "references": self.references, "cves": self.cves,
            "preconditions": self.preconditions, "validation_plan": self.validation_plan,
            "severity": self.severity, "confidence": self.confidence,
            "status": self.status, "conclusion": self.conclusion,
            "category": self.category, "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Hypothesis":
        return cls(
            id=d.get("id", ""), asset=d.get("asset", ""), service=d.get("service", ""),
            observation=d.get("observation", ""), evidence=list(d.get("evidence", [])),
            references=list(d.get("references", [])), cves=list(d.get("cves", [])),
            preconditions=list(d.get("preconditions", [])),
            validation_plan=d.get("validation_plan", ""),
            severity=d.get("severity", "info"), confidence=d.get("confidence", "low"),
            status=d.get("status", STATUS_UNVERIFIED), conclusion=d.get("conclusion", ""),
            category=d.get("category", ""), created_at=d.get("created_at", _now()),
        )


def _normalize_severity(s: str) -> str:
    s = (s or "").strip().lower()
    return s if s in SEVERITY_ORDER else "info"


def _normalize_confidence(c: str) -> str:
    c = (c or "").strip().lower()
    return c if c in CONFIDENCE_ORDER else "low"


def _normalize_status(s: str) -> str:
    s = (s or "").strip().lower().replace(" ", "_")
    return s if s in STATUS_ORDER else STATUS_UNVERIFIED


# ---------------------------------------------------------------------------
# Research sources — pluggable, offline-first
# ---------------------------------------------------------------------------

class ResearchSource:
    """Base class. A source returns 'leads': dicts with title/category/severity/
    references/cves/validation that seed or enrich hypotheses."""
    name = "source"

    def available(self, online: bool) -> bool:
        return True

    def query(self, fp: ServiceFingerprint, online: bool) -> list[dict]:
        raise NotImplementedError


class LocalKnowledgeBase(ResearchSource):
    """Offline knowledge modules loaded from knowledge/*.json plus the operator's
    cheatsheets. Always available; this is what makes research work with no
    internet and a single local model."""
    name = "local-kb"

    def __init__(self, kb_dir: str = "knowledge", extra_notes: str = ""):
        self.kb_dir = kb_dir
        self.extra_notes = extra_notes
        self._modules: list[dict] = []
        self._load()

    def _load(self) -> None:
        self._modules = []
        if os.path.isdir(self.kb_dir):
            for name in sorted(os.listdir(self.kb_dir)):
                if not name.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(self.kb_dir, name), encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and data.get("service"):
                        self._modules.append(data)
                except (json.JSONDecodeError, OSError):
                    continue

    def module_for(self, fp: ServiceFingerprint) -> dict | None:
        svc = (fp.service or "").lower()
        for mod in self._modules:
            aliases = [a.lower() for a in mod.get("aliases", [])] + [mod["service"].lower()]
            if svc and svc in aliases:
                return mod
            if str(fp.port) in [str(p) for p in mod.get("ports", [])]:
                return mod
        return None

    def query(self, fp: ServiceFingerprint, online: bool) -> list[dict]:
        mod = self.module_for(fp)
        if not mod:
            return []
        leads: list[dict] = []
        for chk in mod.get("checks", []):
            leads.append({
                "title": chk.get("title", ""),
                "category": chk.get("category", "configuration"),
                "severity": chk.get("severity", "info"),
                "observation": chk.get("when", ""),
                "validation": chk.get("validation", ""),
                "references": chk.get("references", []),
                "cves": chk.get("cves", []),
                "source": self.name,
            })
        for cred in mod.get("default_credentials", []):
            leads.append({
                "title": f"Documented default credentials for {cred.get('product','this product')}",
                "category": "authentication",
                "severity": "high",
                "observation": f"{cred.get('product','')} ships with documented default credentials",
                "validation": ("Try the single documented default credential ONCE, "
                               "with operator approval and within scope. No brute-force."),
                "references": [cred.get("ref", "")] if cred.get("ref") else [],
                "cves": [],
                "default_credential": {"user": cred.get("user", ""), "pass": cred.get("pass", "")},
                "source": self.name,
            })
        return leads


class NVDSource(ResearchSource):
    """Best-effort NVD CVE lookup by product keyword. Only used when online.

    NVD's public API is rate-limited; this makes a single short, polite request
    and fails quietly (returns []) on any error, so research never hangs or
    breaks when the network is unavailable."""
    name = "nvd"
    API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def available(self, online: bool) -> bool:
        return online

    def query(self, fp: ServiceFingerprint, online: bool) -> list[dict]:
        if not online:
            return []
        keyword = (fp.product or fp.service or "").strip()
        if not keyword:
            return []
        params = {"keywordSearch": keyword, "resultsPerPage": "20"}
        url = f"{self.API}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "xs-ai-research"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return []
        return self.parse(data, fp)

    @staticmethod
    def parse(data: dict, fp: ServiceFingerprint) -> list[dict]:
        """Turn an NVD API response into leads, applying version applicability."""
        leads: list[dict] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            if not cid:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            # severity from CVSS if present
            severity = "medium"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    sev = metrics[key][0].get("cvssData", {}).get("baseSeverity", "")
                    if sev:
                        severity = sev.lower()
                    break
            # extract an affected version range from CPE configurations
            affected = NVDSource._affected_range(cve)
            status, confidence, rationale = assess_cve_applicability(fp, affected)
            if status == STATUS_NOT_APPLICABLE:
                continue  # drop CVEs the detected version rules out
            leads.append({
                "title": f"{cid}: {desc[:140]}",
                "category": "cve",
                "severity": _normalize_severity(severity),
                "observation": f"NVD lists {cid} for {fp.product or fp.service}",
                "validation": f"Verify applicability: {rationale}. Confirm only by testing.",
                "references": [f"https://nvd.nist.gov/vuln/detail/{cid}"],
                "cves": [cid],
                "status": status, "confidence": confidence,
                "source": "nvd",
            })
        return leads

    @staticmethod
    def _affected_range(cve: dict) -> dict:
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    rng = {}
                    if cpe.get("versionStartIncluding"):
                        rng["version_start"] = cpe["versionStartIncluding"]
                    if cpe.get("versionEndExcluding"):
                        rng["version_end_excluding"] = cpe["versionEndExcluding"]
                    if cpe.get("versionEndIncluding"):
                        rng["version_end_including"] = cpe["versionEndIncluding"]
                    if rng:
                        return rng
        return {}


# Extensible registry. Additional sources (CISA KEV, GitHub Security Advisories,
# vendor advisories, OWASP, MITRE ATT&CK) can be registered here without
# touching the engine — each only needs to implement query().
def default_sources(kb_dir: str = "knowledge", extra_notes: str = "") -> list[ResearchSource]:
    return [LocalKnowledgeBase(kb_dir=kb_dir, extra_notes=extra_notes), NVDSource()]


# ---------------------------------------------------------------------------
# Research engine
# ---------------------------------------------------------------------------

RESEARCH_SYSTEM = """\
You are the Service Researcher on an authorized red-team. Given a discovered
service and research leads, produce EVIDENCE-BASED, testable vulnerability
hypotheses. You never claim a vulnerability exists merely because a CVE mentions
the product — consider version, configuration, and available evidence.

Respond with a SINGLE JSON object, no prose outside it:
{"hypotheses": [
  {
    "observation": "what was seen",
    "category": "authentication|configuration|cve|attack-surface",
    "severity": "critical|high|medium|low|info",   // impact IF true
    "confidence": "high|medium|low",                // how sure you are
    "status": "confirmed|strongly_suspected|potential_config|unverified|not_applicable",
    "preconditions": ["..."],
    "cves": ["CVE-..."],
    "references": ["url"],
    "validation_plan": "a SAFE, non-invasive check; no brute-force",
    "conclusion": ""
  }
]}
severity and confidence are SEPARATE: a critical bug with weak evidence is low
confidence, not a confirmed finding. Prefer fewer, well-supported hypotheses."""


@dataclass
class ResearchEngine:
    sources: list[ResearchSource] = field(default_factory=lambda: default_sources())
    online: bool = False

    def gather_leads(self, fp: ServiceFingerprint) -> list[dict]:
        leads: list[dict] = []
        for src in self.sources:
            if not src.available(self.online):
                continue
            try:
                leads.extend(src.query(fp, self.online))
            except Exception:
                continue  # a misbehaving source must never break research
        return leads

    def _hypotheses_from_leads(self, fp: ServiceFingerprint, asset: str,
                               leads: list[dict], start_idx: int) -> list[Hypothesis]:
        """Deterministic, offline hypotheses straight from source leads. Used as
        the baseline and as the fallback when no model is available."""
        out: list[Hypothesis] = []
        for i, lead in enumerate(leads, start=start_idx):
            status = _normalize_status(lead.get("status", STATUS_UNVERIFIED))
            # a KB config/auth lead with no on-target evidence stays a possibility
            if "status" not in lead:
                status = (STATUS_POTENTIAL_CONFIG if lead.get("category") == "configuration"
                          else STATUS_UNVERIFIED)
            out.append(Hypothesis(
                id=f"H{i:03d}", asset=asset, service=fp.label(),
                observation=lead.get("observation") or lead.get("title", ""),
                evidence=[f"[{lead.get('source','kb')}] {lead.get('title','')}"],
                references=[r for r in lead.get("references", []) if r],
                cves=lead.get("cves", []),
                validation_plan=lead.get("validation", ""),
                severity=_normalize_severity(lead.get("severity", "info")),
                confidence=_normalize_confidence(lead.get("confidence", "low")),
                status=status, category=lead.get("category", ""),
            ))
        return out

    def investigate(self, fp: ServiceFingerprint, asset: str, client=None,
                    start_idx: int = 1) -> list[Hypothesis]:
        """Full investigation: gather leads, let the model synthesize ranked
        hypotheses when available, else fall back to KB-derived hypotheses."""
        leads = self.gather_leads(fp)
        baseline = self._hypotheses_from_leads(fp, asset, leads, start_idx)

        if client is None:
            return sorted(baseline, key=lambda h: h.rank_key(), reverse=True)

        lead_lines = "\n".join(
            f"- [{l.get('source','kb')}][{l.get('category','')}/{l.get('severity','')}] "
            f"{l.get('title','')} {('refs=' + ','.join(l.get('references',[]))) if l.get('references') else ''}"
            for l in leads
        ) or "(no external/local leads found)"
        prompt = (
            f"Target asset: {asset}\n"
            f"Service: {fp.label()}  (identification: {fp.reliability})\n"
            f"Banner: {fp.banner or '(none)'}\n"
            f"Detected version: {fp.version or 'unknown'}\n\n"
            f"Research leads:\n{lead_lines}\n\n"
            f"Produce ranked vulnerability hypotheses as the JSON schema requires."
        )
        try:
            # routes through the service_researcher role → whatever model the
            # operator mapped to it (falls back to the executor model)
            raw = client.run_phase("service_researcher", prompt, RESEARCH_SYSTEM, want_json=True)
            obj = _loads_relaxed(raw)
        except Exception:
            obj = None

        if not obj or not isinstance(obj.get("hypotheses"), list):
            return sorted(baseline, key=lambda h: h.rank_key(), reverse=True)

        out: list[Hypothesis] = []
        for i, h in enumerate(obj["hypotheses"], start=start_idx):
            if not isinstance(h, dict):
                continue
            out.append(Hypothesis(
                id=f"H{i:03d}", asset=asset, service=fp.label(),
                observation=str(h.get("observation", "")).strip(),
                evidence=[str(e) for e in h.get("evidence", [])] or
                         [f"model synthesis over {len(leads)} lead(s)"],
                references=[str(r) for r in h.get("references", []) if r],
                cves=[str(c) for c in h.get("cves", []) if c],
                preconditions=[str(p) for p in h.get("preconditions", []) if p],
                validation_plan=str(h.get("validation_plan", "")).strip(),
                severity=_normalize_severity(h.get("severity", "info")),
                confidence=_normalize_confidence(h.get("confidence", "low")),
                status=_normalize_status(h.get("status", STATUS_UNVERIFIED)),
                conclusion=str(h.get("conclusion", "")).strip(),
                category=str(h.get("category", "")).strip(),
            ))
        if not out:
            return sorted(baseline, key=lambda h: h.rank_key(), reverse=True)
        return sorted(out, key=lambda h: h.rank_key(), reverse=True)


def _loads_relaxed(text: str) -> dict | None:
    """Tolerant JSON extraction (fences/prose/control chars) for model replies."""
    s = (text or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1], strict=False)
                except json.JSONDecodeError:
                    return None
    return None
