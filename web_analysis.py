#!/usr/bin/env python3
"""
xs-ai web_analysis — AI-assisted website analysis and prioritization.

Connects the crawler graph to the existing investigation and hypothesis systems.
Prioritizes pages by actual metadata/evidence, not URL keywords alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Page categorization (evidence-based, not URL-keyword-based)
# ---------------------------------------------------------------------------

CATEGORY_AUTH = "authentication"
CATEGORY_ADMIN = "administrative"
CATEGORY_API = "api_endpoint"
CATEGORY_SEARCH = "search_functionality"
CATEGORY_FILE = "file_functionality"
CATEGORY_PARAMETERIZED = "parameterized"
CATEGORY_DOCS = "documentation"
CATEGORY_INTERESTING = "potentially_interesting"

CATEGORIES = [CATEGORY_AUTH, CATEGORY_ADMIN, CATEGORY_API, CATEGORY_SEARCH,
              CATEGORY_FILE, CATEGORY_PARAMETERIZED, CATEGORY_DOCS, CATEGORY_INTERESTING]


@dataclass
class PageAnalysis:
    page_id: str
    url: str
    categories: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    why_interesting: str = ""
    missing_info: list[str] = field(default_factory=list)
    security_implications: list[str] = field(default_factory=list)
    recommended_steps: list[str] = field(default_factory=list)
    confidence: str = "low"  # low / medium / high
    priority: int = 0  # 0=lowest

    def to_dict(self) -> dict:
        return {
            "page_id": self.page_id, "url": self.url,
            "categories": self.categories, "evidence": self.evidence,
            "why_interesting": self.why_interesting,
            "missing_info": self.missing_info,
            "security_implications": self.security_implications,
            "recommended_steps": self.recommended_steps,
            "confidence": self.confidence, "priority": self.priority,
        }


# Heuristic signals — each returns (category, evidence_text, confidence_boost) or None
_AUTH_SIGNALS = [
    (re.compile(r"<form[^>]*>.*?(?:password|passwd|login|signin|auth)", re.I | re.DOTALL),
     "HTML form with password/login fields"),
    (re.compile(r"<input[^>]*type=[\"']password[\"']", re.I),
     "password input field"),
]

_ADMIN_SIGNALS = [
    (re.compile(r"(?:dashboard|control.?panel|admin(?:istrat))", re.I),
     "admin/dashboard content keywords"),
]

_API_SIGNALS = [
    (re.compile(r"application/json", re.I), "JSON content type"),
    (re.compile(r"/api/|/v\d+/|/rest/|/graphql", re.I), "API path pattern"),
    (re.compile(r"swagger|openapi", re.I), "API documentation framework"),
]

_SEARCH_SIGNALS = [
    (re.compile(r"<input[^>]*(?:name=[\"'](?:q|query|search|s)[\"']|type=[\"']search[\"'])", re.I),
     "search input field"),
]

_FILE_SIGNALS = [
    (re.compile(r"<input[^>]*type=[\"']file[\"']", re.I), "file upload field"),
    (re.compile(r"(?:download|upload|attachment|export)", re.I), "file operation keywords"),
]


def _classify_page_heuristic(url: str, title: str, content_type: str,
                             headers: dict, query_params: str) -> list[tuple[str, str, str]]:
    """Classify a page by metadata alone (no body needed for many checks)."""
    results: list[tuple[str, str, str]] = []
    path = url.lower()

    # parameterized pages
    if query_params:
        params = query_params.split("&")
        results.append((CATEGORY_PARAMETERIZED,
                        f"URL has {len(params)} query parameter(s): {query_params[:80]}",
                        "medium"))

    # API endpoint (by path and content type)
    if content_type == "application/json" or any(
            p in path for p in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql")):
        evidence = []
        if content_type == "application/json":
            evidence.append("serves JSON content")
        if any(p in path for p in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql")):
            evidence.append("API path pattern in URL")
        results.append((CATEGORY_API, "; ".join(evidence), "medium"))

    # server header
    server = headers.get("server", headers.get("Server", ""))
    powered = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
    if server or powered:
        results.append((CATEGORY_INTERESTING,
                        f"Server: {server}" + (f", X-Powered-By: {powered}" if powered else ""),
                        "low"))

    return results


def analyze_page(node_dict: dict, body_text: str = "") -> PageAnalysis:
    """Analyze a single crawled page and produce a PageAnalysis."""
    url = node_dict.get("normalized_url", "")
    title = node_dict.get("title", "")
    ct = node_dict.get("content_type", "")
    headers = node_dict.get("headers", {}) if isinstance(node_dict.get("headers"), dict) else {}
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
    query = parsed.query

    pa = PageAnalysis(page_id=node_dict.get("page_id", ""), url=url)

    # heuristic classification from metadata
    for cat, evidence, conf in _classify_page_heuristic(url, title, ct, headers, query):
        if cat not in pa.categories:
            pa.categories.append(cat)
        pa.evidence.append(evidence)
        if conf == "high" or (conf == "medium" and pa.confidence != "high"):
            pa.confidence = conf

    # body-based classification (when available)
    if body_text:
        for regex, desc in _AUTH_SIGNALS:
            if regex.search(body_text):
                if CATEGORY_AUTH not in pa.categories:
                    pa.categories.append(CATEGORY_AUTH)
                pa.evidence.append(desc)
                pa.confidence = "high"
                pa.security_implications.append("Authentication interface — test for weak credentials, brute-force protections, session handling")
                pa.recommended_steps.append("Inspect login form fields and hidden inputs")
                pa.recommended_steps.append("Check for account lockout and rate limiting")
                break

        for regex, desc in _ADMIN_SIGNALS:
            if regex.search(body_text) or regex.search(title):
                if CATEGORY_ADMIN not in pa.categories:
                    pa.categories.append(CATEGORY_ADMIN)
                pa.evidence.append(desc)
                pa.security_implications.append("Administrative interface — verify access controls and authentication requirements")
                pa.recommended_steps.append("Verify authentication is required for all admin functions")

        for regex, desc in _API_SIGNALS:
            if regex.search(body_text):
                if CATEGORY_API not in pa.categories:
                    pa.categories.append(CATEGORY_API)
                pa.evidence.append(desc)

        for regex, desc in _SEARCH_SIGNALS:
            if regex.search(body_text):
                if CATEGORY_SEARCH not in pa.categories:
                    pa.categories.append(CATEGORY_SEARCH)
                pa.evidence.append(desc)
                pa.security_implications.append("Search functionality — potential for injection or information disclosure")
                pa.recommended_steps.append("Test search input handling and output encoding")

        for regex, desc in _FILE_SIGNALS:
            if regex.search(body_text):
                if CATEGORY_FILE not in pa.categories:
                    pa.categories.append(CATEGORY_FILE)
                pa.evidence.append(desc)
                pa.security_implications.append("File functionality — check upload validation, path traversal, download authorization")
                pa.recommended_steps.append("Inspect file upload restrictions and storage")

    # priority scoring
    priority_map = {
        CATEGORY_AUTH: 90, CATEGORY_ADMIN: 85, CATEGORY_FILE: 80,
        CATEGORY_API: 75, CATEGORY_SEARCH: 70, CATEGORY_PARAMETERIZED: 50,
        CATEGORY_DOCS: 20, CATEGORY_INTERESTING: 30,
    }
    pa.priority = max((priority_map.get(c, 10) for c in pa.categories), default=0)

    # why interesting
    if pa.categories:
        pa.why_interesting = f"Page classified as: {', '.join(pa.categories)}"
    if not pa.categories and node_dict.get("http_status", 0) in (401, 403):
        pa.categories.append(CATEGORY_INTERESTING)
        pa.evidence.append(f"HTTP {node_dict['http_status']} — access restricted")
        pa.why_interesting = "Access-restricted page (may indicate protected functionality)"
        pa.priority = 60

    # missing info
    if not body_text:
        pa.missing_info.append("Page body not available for deep analysis")
    if not title:
        pa.missing_info.append("No page title extracted")

    return pa


def analyze_graph(graph_dict: dict) -> list[PageAnalysis]:
    """Analyze all pages in a graph, return prioritized list."""
    results = []
    for pid, node in graph_dict.get("nodes", {}).items():
        if node.get("crawl_status") != "crawled":
            continue
        pa = analyze_page(node)
        if pa.categories:
            results.append(pa)
    results.sort(key=lambda p: -p.priority)
    return results


# ---------------------------------------------------------------------------
# AI-enhanced analysis (uses the existing AI backend)
# ---------------------------------------------------------------------------

_ANALYZE_SYSTEM = """You are a security analyst reviewing crawled web pages.
Given page metadata and evidence, assess its security relevance.
Respond with JSON:
{
  "categories": ["category1", ...],
  "why_interesting": "one sentence",
  "security_implications": ["implication1", ...],
  "recommended_steps": ["step1", ...],
  "confidence": "low|medium|high",
  "missing_info": ["what else to check"]
}
Categories: authentication, administrative, api_endpoint, search_functionality,
file_functionality, parameterized, documentation, potentially_interesting.
Base your assessment on ACTUAL evidence, not URL keywords alone.
A page with /admin/ in the URL is not automatically an admin page."""


def ai_analyze_page(client: Any, node_dict: dict,
                    heuristic: PageAnalysis | None = None) -> PageAnalysis:
    """Use the AI to enhance a page analysis. Falls back to heuristic."""
    if heuristic is None:
        heuristic = analyze_page(node_dict)
    if client is None:
        return heuristic

    prompt = f"""Analyze this crawled page:
URL: {node_dict.get('normalized_url', '')}
Title: {node_dict.get('title', '')}
Status: {node_dict.get('http_status', 0)}
Content-Type: {node_dict.get('content_type', '')}
Size: {node_dict.get('response_size', 0)} bytes
Depth: {node_dict.get('crawl_depth', 0)}
Headers: {json.dumps(node_dict.get('headers', {}), indent=1)}
Redirect chain: {node_dict.get('redirect_chain', [])}
Incoming links: {len(node_dict.get('incoming_links', []))}
Outgoing links: {len(node_dict.get('outgoing_links', []))}
Heuristic categories: {heuristic.categories}
Heuristic evidence: {heuristic.evidence}
"""
    try:
        raw = client.run_phase("recon", prompt, system=_ANALYZE_SYSTEM, want_json=True)
        data = json.loads(raw)
        for cat in data.get("categories", []):
            if cat in CATEGORIES and cat not in heuristic.categories:
                heuristic.categories.append(cat)
        if data.get("why_interesting"):
            heuristic.why_interesting = data["why_interesting"]
        for imp in data.get("security_implications", []):
            if imp not in heuristic.security_implications:
                heuristic.security_implications.append(imp)
        for step in data.get("recommended_steps", []):
            if step not in heuristic.recommended_steps:
                heuristic.recommended_steps.append(step)
        if data.get("confidence") in ("low", "medium", "high"):
            heuristic.confidence = data["confidence"]
        for mi in data.get("missing_info", []):
            if mi not in heuristic.missing_info:
                heuristic.missing_info.append(mi)
    except Exception:
        pass  # fall back to heuristic
    return heuristic


# ---------------------------------------------------------------------------
# Investigation queue
# ---------------------------------------------------------------------------

@dataclass
class InvestigationItem:
    page_id: str
    url: str
    status: str = "queued"  # queued / analyzing / analyzed / excluded / paused
    analysis: PageAnalysis | None = None
    hypotheses: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "page_id": self.page_id, "url": self.url, "status": self.status,
            "analysis": self.analysis.to_dict() if self.analysis else None,
            "hypotheses": self.hypotheses,
        }


@dataclass
class InvestigationQueue:
    items: dict[str, InvestigationItem] = field(default_factory=dict)
    paused: bool = False
    cancelled: bool = False

    def add(self, page_id: str, url: str) -> InvestigationItem:
        if page_id not in self.items:
            self.items[page_id] = InvestigationItem(page_id=page_id, url=url)
        return self.items[page_id]

    def add_group(self, pages: list[tuple[str, str]]) -> int:
        count = 0
        for pid, url in pages:
            if pid not in self.items:
                self.add(pid, url)
                count += 1
        return count

    def exclude(self, page_id: str) -> None:
        if page_id in self.items:
            self.items[page_id].status = "excluded"

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def cancel(self):
        self.cancelled = True

    def queued(self) -> list[InvestigationItem]:
        return [i for i in self.items.values() if i.status == "queued"]

    def analyzed(self) -> list[InvestigationItem]:
        return [i for i in self.items.values() if i.status == "analyzed"]

    def stats(self) -> dict:
        counts: dict[str, int] = {}
        for item in self.items.values():
            counts[item.status] = counts.get(item.status, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "paused": self.paused, "cancelled": self.cancelled,
            "stats": self.stats(),
            "items": {pid: item.to_dict() for pid, item in self.items.items()},
        }


def run_investigation(queue: InvestigationQueue, graph_dict: dict,
                      client: Any = None) -> None:
    """Process queued investigation items."""
    for item in queue.queued():
        if queue.paused or queue.cancelled:
            break
        item.status = "analyzing"
        node = graph_dict.get("nodes", {}).get(item.page_id, {})
        heuristic = analyze_page(node)
        item.analysis = ai_analyze_page(client, node, heuristic) if client else heuristic
        item.status = "analyzed"
