#!/usr/bin/env python3
"""
xs-ai vendor_advisories — modular vendor security advisory research.

Extends the existing NVD/CVE pipeline with official vendor advisory sources.
Does NOT introduce a second CVE database. Reuses the existing vulnerability
matching and evidence systems.  Clearly distinguishes official advisory
information from AI interpretations.

Does NOT fabricate advisory information.
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
# Advisory data model
# ---------------------------------------------------------------------------

@dataclass
class VendorAdvisory:
    advisory_id: str
    vendor: str
    product: str
    title: str = ""
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    severity: str = ""
    cves: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    exploitation_conditions: list[str] = field(default_factory=list)
    description: str = ""
    url: str = ""
    retrieval_timestamp: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "vendor": self.vendor,
            "product": self.product,
            "title": self.title,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "severity": self.severity,
            "cves": self.cves,
            "prerequisites": self.prerequisites,
            "exploitation_conditions": self.exploitation_conditions,
            "description": self.description[:500],
            "url": self.url,
            "retrieval_timestamp": self.retrieval_timestamp,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

class AdvisoryProvider:
    """Base class for vendor advisory providers."""
    vendor: str = ""

    def search(self, product: str, version: str = "") -> list[VendorAdvisory]:
        raise NotImplementedError

    def get_advisory(self, advisory_id: str) -> VendorAdvisory | None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Microsoft Security Response Center (MSRC)
# ---------------------------------------------------------------------------

class MSRCProvider(AdvisoryProvider):
    vendor = "Microsoft"

    def __init__(self):
        self._base = "https://api.msrc.microsoft.com"

    def search(self, product: str, version: str = "") -> list[VendorAdvisory]:
        """Search MSRC for advisories. Uses the CVRF API."""
        now = datetime.datetime.now()
        year_month = now.strftime("%Y-%b")
        url = f"{self._base}/cvrf/v3.0/updates('{year_month}')"
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "xs-ai/1.0",
            })
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read().decode())
        except Exception:
            return []

        results = []
        for entry in data.get("value", []):
            adv_id = entry.get("ID", "")
            if not adv_id:
                continue
            results.append(VendorAdvisory(
                advisory_id=adv_id,
                vendor="Microsoft",
                product=product,
                title=entry.get("InitialReleaseDate", ""),
                url=f"https://msrc.microsoft.com/update-guide/vulnerability/{adv_id}",
                retrieval_timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
                source="MSRC",
            ))
        return results[:20]


# ---------------------------------------------------------------------------
# Apache Security Advisories
# ---------------------------------------------------------------------------

class ApacheProvider(AdvisoryProvider):
    vendor = "Apache"

    # Known Apache product advisory pages
    _ADVISORY_URLS = {
        "httpd": "https://httpd.apache.org/security/json/",
        "tomcat": "https://tomcat.apache.org/security.html",
        "struts": "https://struts.apache.org/announce",
    }

    def search(self, product: str, version: str = "") -> list[VendorAdvisory]:
        """Search Apache advisories for a product."""
        prod_key = product.lower().replace("apache ", "").replace("httpd", "httpd")
        url = self._ADVISORY_URLS.get(prod_key)
        if not url:
            return []

        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "xs-ai/1.0",
                "Accept": "text/html,application/json",
            })
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
        except Exception:
            return []

        # Parse CVE references from the page
        cves = re.findall(r"CVE-\d{4}-\d{4,}", body)
        results = []
        seen = set()
        for cve in cves[:20]:
            if cve in seen:
                continue
            seen.add(cve)
            results.append(VendorAdvisory(
                advisory_id=cve,
                vendor="Apache",
                product=product,
                cves=[cve],
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                retrieval_timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
                source="Apache Security",
            ))
        return results


# ---------------------------------------------------------------------------
# Splunk Security Advisories
# ---------------------------------------------------------------------------

class SplunkProvider(AdvisoryProvider):
    vendor = "Splunk"

    def search(self, product: str, version: str = "") -> list[VendorAdvisory]:
        """Search Splunk advisory listing."""
        url = "https://advisory.splunk.com/advisories"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "xs-ai/1.0", "Accept": "text/html",
            })
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
        except Exception:
            return []

        # Extract SVD advisory IDs
        advisories = re.findall(r"SVD-\d{4}-\d{4}", body)
        results = []
        seen = set()
        for svd in advisories[:20]:
            if svd in seen:
                continue
            seen.add(svd)
            results.append(VendorAdvisory(
                advisory_id=svd,
                vendor="Splunk",
                product="Splunk",
                url=f"https://advisory.splunk.com/{svd}",
                retrieval_timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
                source="Splunk Advisory",
            ))
        return results


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, type[AdvisoryProvider]] = {
    "microsoft": MSRCProvider,
    "apache": ApacheProvider,
    "splunk": SplunkProvider,
}


def get_provider(vendor: str) -> AdvisoryProvider | None:
    cls = PROVIDERS.get(vendor.lower())
    return cls() if cls else None


def search_advisories(product: str, version: str = "",
                      vendor: str = "") -> list[VendorAdvisory]:
    """Search all (or a specific) vendor for advisories."""
    results = []
    if vendor:
        prov = get_provider(vendor)
        if prov:
            results.extend(prov.search(product, version))
    else:
        for name, cls in PROVIDERS.items():
            try:
                results.extend(cls().search(product, version))
            except Exception:
                pass
    return results


# ---------------------------------------------------------------------------
# Integration with existing research engine
# ---------------------------------------------------------------------------

def advisories_to_leads(advisories: list[VendorAdvisory]) -> list[dict]:
    """Convert vendor advisories to research engine lead format."""
    leads = []
    for adv in advisories:
        lead = {
            "title": f"[{adv.vendor}] {adv.title or adv.advisory_id}",
            "category": "vulnerability",
            "severity": adv.severity or "medium",
            "source": f"vendor-advisory:{adv.source}",
            "cves": adv.cves,
            "references": [adv.url] if adv.url else [],
            "description": adv.description[:300] if adv.description else "",
            "affected_versions": adv.affected_versions,
            "fixed_versions": adv.fixed_versions,
        }
        leads.append(lead)
    return leads


def format_advisory_context(advisories: list[VendorAdvisory],
                            max_items: int = 5) -> str:
    if not advisories:
        return ""
    lines = ["--- Vendor Security Advisories ---"]
    for adv in advisories[:max_items]:
        lines.append(f"\n  [{adv.advisory_id}] {adv.vendor}: {adv.title or '(no title)'}")
        if adv.cves:
            lines.append(f"  CVEs: {', '.join(adv.cves)}")
        if adv.severity:
            lines.append(f"  Severity: {adv.severity}")
        if adv.affected_versions:
            lines.append(f"  Affected: {', '.join(adv.affected_versions[:5])}")
        if adv.url:
            lines.append(f"  URL: {adv.url}")
        lines.append("  Source: official vendor advisory (not AI-generated)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_advisories(advisories: list[VendorAdvisory], path: str) -> None:
    data = [a.to_dict() for a in advisories]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_advisories(path: str) -> list[VendorAdvisory]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [VendorAdvisory(**{k: v for k, v in d.items()
                              if k in VendorAdvisory.__dataclass_fields__})
            for d in data]
