#!/usr/bin/env python3
"""
xs-ai investigation — unified cross-component investigation engine.

Bridges the existing ResearchEngine with new modules:
  crawler, web_analysis, atomic_red_team, navigator, caldera_adapter,
  caldera_ot, vendor_advisories.

Does NOT replace any existing module — augments them through a single
coordination layer that client.py can call.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

# Optional imports — each module is graceful-absent
try:
    import crawler
except ImportError:
    crawler = None  # type: ignore
try:
    import explorer
except ImportError:
    explorer = None  # type: ignore
try:
    import web_analysis
except ImportError:
    web_analysis = None  # type: ignore
try:
    import atomic_red_team
except ImportError:
    atomic_red_team = None  # type: ignore
try:
    import navigator
except ImportError:
    navigator = None  # type: ignore
try:
    import caldera_adapter
except ImportError:
    caldera_adapter = None  # type: ignore
try:
    import caldera_ot
except ImportError:
    caldera_ot = None  # type: ignore
try:
    import vendor_advisories
except ImportError:
    vendor_advisories = None  # type: ignore
try:
    import research
except ImportError:
    research = None  # type: ignore


# ---------------------------------------------------------------------------
# Investigation context — single object that all modules share
# ---------------------------------------------------------------------------

@dataclass
class InvestigationContext:
    target: str = ""
    scope_guard: Any = None
    client: Any = None          # AI backend
    online: bool = False
    report_dir: str = "reports"

    # Module state (populated lazily)
    website_graph: Any = None
    crawl_state: Any = None
    page_analyses: list = field(default_factory=list)
    investigation_queue: Any = None
    atomic_repo: Any = None
    nav_annotations: list = field(default_factory=list)
    caldera_knowledge: Any = None
    ot_knowledge: Any = None
    advisories: list = field(default_factory=list)
    explorer_server: Any = None

    def available_modules(self) -> list[str]:
        mods = []
        if crawler is not None:
            mods.append("crawler")
        if explorer is not None:
            mods.append("explorer")
        if web_analysis is not None:
            mods.append("web_analysis")
        if atomic_red_team is not None:
            mods.append("atomic_red_team")
        if navigator is not None:
            mods.append("navigator")
        if caldera_adapter is not None:
            mods.append("caldera")
        if caldera_ot is not None:
            mods.append("caldera_ot")
        if vendor_advisories is not None:
            mods.append("vendor_advisories")
        return mods


# ---------------------------------------------------------------------------
# Crawl operations
# ---------------------------------------------------------------------------

def start_crawl(ctx: InvestigationContext, url: str,
                max_depth: int = 10, max_pages: int = 500,
                allow_subdomains: bool = False,
                on_progress: Any = None) -> dict:
    if crawler is None:
        return {"error": "crawler module not available"}

    ok, reason = crawler.validate_crawl_target(url, ctx.scope_guard)
    if not ok:
        return {"error": reason}

    config = crawler.CrawlConfig(
        start_url=url,
        max_depth=max_depth,
        max_pages=max_pages,
        allow_subdomains=allow_subdomains,
        scope_guard=ctx.scope_guard,
        on_progress=on_progress,
    )
    graph, state = crawler.crawl(config)
    ctx.website_graph = graph
    ctx.crawl_state = state
    return graph.stats()


def get_crawl_summary(ctx: InvestigationContext) -> str:
    if crawler is None or ctx.website_graph is None:
        return "No crawl data available."
    return crawler.format_crawl_summary(ctx.website_graph)


# ---------------------------------------------------------------------------
# Explorer
# ---------------------------------------------------------------------------

def start_explorer_ui(ctx: InvestigationContext, port: int = 8477) -> str:
    if explorer is None:
        return "Explorer module not available."
    if ctx.website_graph is None:
        return "No crawl data — run :crawl first."

    graph_data = {
        "nodes": [],
        "stats": ctx.website_graph.stats(),
    }
    for pid, node in ctx.website_graph.nodes.items():
        nd = {
            "id": pid,
            "url": node.url if hasattr(node, "url") else (list(node.urls)[0] if node.urls else ""),
            "title": node.title or "",
            "status": node.status,
            "depth": node.depth,
            "content_type": node.content_type or "",
            "size": node.size,
            "outgoing": list(node.outgoing),
            "incoming": list(node.incoming),
        }
        graph_data["nodes"].append(nd)

    server, url = explorer.start_explorer(graph_data, port=port)
    ctx.explorer_server = server
    return url


def stop_explorer_ui(ctx: InvestigationContext) -> None:
    if explorer is not None and ctx.explorer_server is not None:
        explorer.stop_explorer(ctx.explorer_server)
        ctx.explorer_server = None


# ---------------------------------------------------------------------------
# Web analysis + investigation queue
# ---------------------------------------------------------------------------

def analyze_crawled_pages(ctx: InvestigationContext) -> list[dict]:
    if web_analysis is None or ctx.website_graph is None:
        return []

    graph_dict = {}
    for pid, node in ctx.website_graph.nodes.items():
        graph_dict[pid] = {
            "url": node.url if hasattr(node, "url") else (list(node.urls)[0] if node.urls else ""),
            "title": node.title or "",
            "status": node.status,
            "content_type": node.content_type or "",
            "size": node.size,
            "headers": node.headers if hasattr(node, "headers") else {},
            "depth": node.depth,
        }

    analyses = web_analysis.analyze_graph(graph_dict)
    ctx.page_analyses = analyses
    return analyses


def create_investigation_queue(ctx: InvestigationContext,
                               page_ids: list[str] | None = None) -> str:
    if web_analysis is None:
        return "Web analysis module not available."
    if not ctx.page_analyses:
        return "No page analyses — run :web-analyze first."

    ctx.investigation_queue = web_analysis.InvestigationQueue()
    items = page_ids or [a.get("page_id", "") for a in ctx.page_analyses[:20]]
    for pid in items:
        analysis = next((a for a in ctx.page_analyses if a.get("page_id") == pid), None)
        if analysis:
            ctx.investigation_queue.add(web_analysis.InvestigationItem(
                page_id=pid,
                url=analysis.get("url", ""),
                priority=analysis.get("priority", 0),
                categories=analysis.get("categories", []),
            ))
    return f"Queue created with {len(ctx.investigation_queue.items)} items."


# ---------------------------------------------------------------------------
# Atomic Red Team
# ---------------------------------------------------------------------------

def import_atomic_repo(ctx: InvestigationContext, path: str) -> dict:
    if atomic_red_team is None:
        return {"error": "atomic_red_team module not available"}
    repo = atomic_red_team.AtomicRepository()
    stats = repo.import_directory(path)
    ctx.atomic_repo = repo
    return stats


def search_atomic_tests(ctx: InvestigationContext,
                        query: str) -> list[dict]:
    if ctx.atomic_repo is None:
        return []
    tests = ctx.atomic_repo.search(query)
    return [t.to_dict() for t in tests[:10]]


def atomic_context_for_hypothesis(ctx: InvestigationContext,
                                   technique_id: str) -> str:
    if ctx.atomic_repo is None or atomic_red_team is None:
        return ""
    tests = ctx.atomic_repo.lookup(technique_id)
    return atomic_red_team.format_atomic_context(tests)


# ---------------------------------------------------------------------------
# ATT&CK Navigator
# ---------------------------------------------------------------------------

def generate_navigator_layer(ctx: InvestigationContext,
                              hypotheses: list[dict],
                              findings: list[str] | None = None) -> str:
    if navigator is None:
        return "Navigator module not available."
    path = navigator.export_investigation(
        ctx.target, hypotheses, findings, output_dir=ctx.report_dir)
    return path


def add_navigator_annotation(ctx: InvestigationContext,
                              technique_id: str,
                              evidence_level: str = "unverified",
                              **kwargs) -> None:
    if navigator is None:
        return
    ann = navigator.TechniqueAnnotation(
        technique_id=technique_id,
        evidence_level=evidence_level,
        **kwargs,
    )
    ctx.nav_annotations.append(ann)


# ---------------------------------------------------------------------------
# Caldera
# ---------------------------------------------------------------------------

def connect_caldera(ctx: InvestigationContext,
                    url: str = "", api_key: str = "") -> dict:
    if caldera_adapter is None:
        return {"error": "caldera_adapter module not available"}
    config = caldera_adapter.CalderaConfig(
        base_url=url or os.environ.get("CALDERA_URL", ""),
        api_key=api_key or os.environ.get("CALDERA_API_KEY", ""),
        enabled=True,
    )
    client = caldera_adapter.CalderaClient(config)
    ok, msg = client.health_check()
    if not ok:
        return {"error": f"Caldera connection failed: {msg}"}
    kb = caldera_adapter.CalderaKnowledge()
    stats = kb.import_from_client(client)
    ctx.caldera_knowledge = kb
    return stats


def caldera_context_for_technique(ctx: InvestigationContext,
                                   technique_id: str) -> str:
    if ctx.caldera_knowledge is None or caldera_adapter is None:
        return ""
    abilities = ctx.caldera_knowledge.lookup_technique(technique_id)
    return caldera_adapter.format_caldera_context(abilities)


# ---------------------------------------------------------------------------
# OT
# ---------------------------------------------------------------------------

def check_ot_protocols(ctx: InvestigationContext,
                       ports: list[int | str]) -> list[dict]:
    if caldera_ot is None:
        return []
    kb = caldera_ot.OTKnowledge()
    findings = kb.scan_ports(ports)
    if findings:
        ctx.ot_knowledge = kb
    return [f.to_dict() for f in findings]


# ---------------------------------------------------------------------------
# Vendor advisories
# ---------------------------------------------------------------------------

def search_vendor_advisories(ctx: InvestigationContext,
                              product: str, version: str = "",
                              vendor: str = "") -> list[dict]:
    if vendor_advisories is None:
        return []
    advs = vendor_advisories.search_advisories(product, version, vendor)
    ctx.advisories.extend(advs)
    return [a.to_dict() for a in advs]


def advisory_context(ctx: InvestigationContext) -> str:
    if vendor_advisories is None or not ctx.advisories:
        return ""
    return vendor_advisories.format_advisory_context(ctx.advisories)


# ---------------------------------------------------------------------------
# Cross-component: enrich hypothesis with all available context
# ---------------------------------------------------------------------------

def enrich_hypothesis(ctx: InvestigationContext,
                      hypothesis: dict) -> str:
    """Build enrichment context for one hypothesis from all modules."""
    parts = []

    technique_id = hypothesis.get("technique_id", "")
    product = hypothesis.get("service", "").split("/")[0] if "/" in hypothesis.get("service", "") else hypothesis.get("service", "")

    # Atomic Red Team tests
    if technique_id:
        atomic_ctx = atomic_context_for_hypothesis(ctx, technique_id)
        if atomic_ctx:
            parts.append(atomic_ctx)

    # Caldera abilities
    if technique_id:
        caldera_ctx = caldera_context_for_technique(ctx, technique_id)
        if caldera_ctx:
            parts.append(caldera_ctx)

    # Vendor advisories
    if product:
        adv_ctx = advisory_context(ctx)
        if adv_ctx:
            parts.append(adv_ctx)

    # OT context
    if ctx.ot_knowledge and caldera_ot is not None:
        ot_ctx = caldera_ot.format_ot_context(ctx.ot_knowledge.findings)
        if ot_ctx:
            parts.append(ot_ctx)

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Full export
# ---------------------------------------------------------------------------

def export_full_report(ctx: InvestigationContext,
                       session_hypotheses: list[dict],
                       session_findings: list[str]) -> dict:
    """Export investigation state across all modules."""
    report: dict[str, Any] = {"target": ctx.target, "modules": {}}

    if ctx.website_graph is not None:
        report["modules"]["crawler"] = ctx.website_graph.stats()

    if ctx.page_analyses:
        report["modules"]["web_analysis"] = {
            "analyzed_pages": len(ctx.page_analyses),
            "interesting": sum(1 for a in ctx.page_analyses
                               if a.get("priority", 0) > 50),
        }

    if ctx.atomic_repo is not None:
        report["modules"]["atomic_red_team"] = ctx.atomic_repo.stats()

    if navigator is not None and session_hypotheses:
        nav_path = generate_navigator_layer(ctx, session_hypotheses, session_findings)
        report["modules"]["navigator"] = {"layer_file": nav_path}

    if ctx.caldera_knowledge is not None:
        report["modules"]["caldera"] = ctx.caldera_knowledge.stats()

    if ctx.ot_knowledge is not None:
        report["modules"]["caldera_ot"] = ctx.ot_knowledge.to_dict()

    if ctx.advisories and vendor_advisories is not None:
        report["modules"]["vendor_advisories"] = {
            "count": len(ctx.advisories),
            "vendors": list({a.vendor for a in ctx.advisories}),
        }

    path = os.path.join(ctx.report_dir, f"investigation_{ctx.target.replace('.', '_')}.json")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report
