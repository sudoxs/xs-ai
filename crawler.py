#!/usr/bin/env python3
"""
xs-ai crawler — website mapping engine.

Maps the structure of an authorized website as a directed graph before deeper
security investigation.  Pure stdlib, no third-party deps.

Design:
- Same-origin by default; configurable subdomain scope.
- Integrates with ScopeGuard for scope enforcement.
- Respects robots.txt.  Never submits forms or performs state-changing requests.
- Crawl pause / resume / cancel via threading Event.
- URL normalization handles fragments, default ports, relative refs, redirects.
- Graph representation: each page is a node; links are directed edges.
"""

from __future__ import annotations

import datetime
import hashlib
import html.parser
import http.client
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_PAGES = 500
DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 0.5
DEFAULT_MAX_RESPONSE = 5 * 1024 * 1024  # 5 MiB
CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
USER_AGENT = "xs-ai-crawler/1.0 (security-research; operator-authorized)"

# Hosts that must never be crawled unless explicitly in scope
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254", "metadata.google.internal",
    "100.100.100.200",
}
BODY_SAMPLE_MAX = 64 * 1024  # 64 KiB of HTML kept on the node for later analysis

_SCHEME_RE = re.compile(r"^https?://", re.I)

# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------

def normalize_url(url: str, base: str = "") -> str:
    """Normalize a URL for deduplication while preserving meaningful query params."""
    if base:
        url = urllib.parse.urljoin(base, url)
    p = urllib.parse.urlparse(url)
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return ""
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return ""
    # strip default ports
    port = p.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    # normalize path
    path = p.path or "/"
    # collapse .. and .
    parts = []
    for seg in path.split("/"):
        if seg == "..":
            if parts:
                parts.pop()
        elif seg != ".":
            parts.append(seg)
    path = "/".join(parts) or "/"
    if not path.startswith("/"):
        path = "/" + path
    # keep query, drop fragment
    query = p.query
    return urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))


def same_origin(url: str, origin: str) -> bool:
    a = urllib.parse.urlparse(url)
    b = urllib.parse.urlparse(origin)
    return (a.scheme == b.scheme and
            (a.hostname or "").lower() == (b.hostname or "").lower() and
            (a.port or (443 if a.scheme == "https" else 80)) ==
            (b.port or (443 if b.scheme == "https" else 80)))


def same_domain(url: str, origin: str, allow_subdomains: bool = False) -> bool:
    if same_origin(url, origin):
        return True
    if not allow_subdomains:
        return False
    a_host = (urllib.parse.urlparse(url).hostname or "").lower()
    b_host = (urllib.parse.urlparse(origin).hostname or "").lower()
    return a_host.endswith("." + b_host) or a_host == b_host


def _is_blocked_host(host: str, scope_guard: Any = None) -> bool:
    """Reject metadata/loopback/link-local always; reject private/reserved
    unless the operator explicitly authorized this host in scope_guard.

    An engagement can legitimately target RFC1918 ranges, so private/reserved
    is gated on operator intent — but loopback, link-local, metadata and
    multicast are never accepted even when the operator says so, since they
    are the SSRF-pivot targets we exist to stop."""
    h = host.lower().strip()
    if h in BLOCKED_HOSTS:
        return True
    if h.endswith(".internal") or h.endswith(".localhost"):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        # unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        # Hard block — never crawlable
        if (ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_unspecified):
            return True
        in_scope = False
        if scope_guard is not None:
            try:
                ok, _ = scope_guard.check(str(ip))
                in_scope = ok
            except Exception:
                in_scope = False
        # Soft block — allowed only when operator opted in via scope
        if (ip.is_private or ip.is_reserved) and not in_scope:
            return True
    except ValueError:
        pass
    return False


def _resolve_and_pin(hostname: str, port: int,
                     scope_guard: Any = None) -> tuple[bool, str, str]:
    """Resolve once, validate every result, return the first allowed IP.
    The caller connects to that IP (not to `hostname` again) to close the
    DNS-rebinding TOCTOU gap where a malicious resolver could flip answers
    between validate and connect."""
    try:
        infos = socket.getaddrinfo(hostname, port,
                                   socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}", ""
    first_blocked = ""
    for _fam, _type, _proto, _canon, sa in infos:
        ip_str = sa[0]
        if _is_blocked_host(ip_str, scope_guard):
            first_blocked = first_blocked or ip_str
            continue
        return True, "ok", ip_str
    if first_blocked:
        return False, (f"DNS rebinding guard: {hostname} resolves to "
                        f"blocked {first_blocked}"), first_blocked
    return False, f"no usable address for {hostname}", ""


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.title: str = ""
        self._in_title = False
        self._title_parts: list[str] = []
        self.canonical: str = ""

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and "href" in d:
            self.links.append(d["href"])
        elif tag == "link" and d.get("rel", "").lower() == "canonical" and "href" in d:
            self.canonical = d["href"]
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title" and self._in_title:
            self._in_title = False
            self.title = "".join(self._title_parts).strip()

    def handle_data(self, data):
        if self._in_title:
            self._title_parts.append(data)


def extract_links(html_text: str, base_url: str) -> tuple[list[str], str, str]:
    """Return (normalized_links, title, canonical_url) from HTML."""
    parser = _LinkParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass
    links = []
    seen = set()
    for href in parser.links:
        norm = normalize_url(href, base_url)
        if norm and norm not in seen:
            seen.add(norm)
            links.append(norm)
    canonical = normalize_url(parser.canonical, base_url) if parser.canonical else ""
    return links, parser.title, canonical


# ---------------------------------------------------------------------------
# Page node (graph vertex)
# ---------------------------------------------------------------------------

@dataclass
class PageNode:
    page_id: str
    original_url: str
    normalized_url: str
    http_status: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    title: str = ""
    content_type: str = ""
    response_size: int = 0
    crawl_depth: int = 0
    parent_id: str = ""
    incoming_links: list[str] = field(default_factory=list)
    outgoing_links: list[str] = field(default_factory=list)
    canonical_url: str = ""
    content_fingerprint: str = ""
    discovery_timestamp: str = ""
    crawl_status: str = "pending"  # pending / crawled / error / skipped / redirect
    error: str = ""
    headers: dict = field(default_factory=dict)
    # Up to BODY_SAMPLE_MAX chars of the HTML body — kept so later analysis
    # (web_analysis.analyze_page) can look for AUTH/FILE/SEARCH signals that
    # live in the response body, not just metadata.
    body_sample: str = ""

    def to_dict(self, include_body: bool = True) -> dict:
        d = {
            "page_id": self.page_id,
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "http_status": self.http_status,
            "redirect_chain": self.redirect_chain,
            "title": self.title,
            "content_type": self.content_type,
            "response_size": self.response_size,
            "crawl_depth": self.crawl_depth,
            "parent_id": self.parent_id,
            "incoming_links": self.incoming_links,
            "outgoing_links": self.outgoing_links,
            "canonical_url": self.canonical_url,
            "content_fingerprint": self.content_fingerprint,
            "discovery_timestamp": self.discovery_timestamp,
            "crawl_status": self.crawl_status,
            "error": self.error,
        }
        if include_body and self.body_sample:
            # Already truncated at capture time; stored as-is.
            d["body_sample"] = self.body_sample
        return d


# ---------------------------------------------------------------------------
# Website graph
# ---------------------------------------------------------------------------

@dataclass
class WebsiteGraph:
    origin: str = ""
    nodes: dict[str, PageNode] = field(default_factory=dict)
    url_to_id: dict[str, str] = field(default_factory=dict)
    _id_counter: int = 0

    def add_node(self, url: str, depth: int = 0, parent_id: str = "") -> PageNode:
        norm = normalize_url(url)
        if norm in self.url_to_id:
            node = self.nodes[self.url_to_id[norm]]
            if parent_id and parent_id not in node.incoming_links:
                node.incoming_links.append(parent_id)
            return node
        self._id_counter += 1
        pid = f"P{self._id_counter:04d}"
        node = PageNode(
            page_id=pid,
            original_url=url,
            normalized_url=norm,
            crawl_depth=depth,
            parent_id=parent_id,
            incoming_links=[parent_id] if parent_id else [],
            discovery_timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
        )
        self.nodes[pid] = node
        self.url_to_id[norm] = pid
        return node

    def get_by_url(self, url: str) -> PageNode | None:
        norm = normalize_url(url)
        pid = self.url_to_id.get(norm)
        return self.nodes.get(pid) if pid else None

    def add_edge(self, from_id: str, to_id: str) -> None:
        if from_id in self.nodes and to_id not in self.nodes[from_id].outgoing_links:
            self.nodes[from_id].outgoing_links.append(to_id)
        if to_id in self.nodes and from_id not in self.nodes[to_id].incoming_links:
            self.nodes[to_id].incoming_links.append(from_id)

    def stats(self) -> dict:
        statuses: dict[int, int] = {}
        for n in self.nodes.values():
            statuses[n.http_status] = statuses.get(n.http_status, 0) + 1
        return {
            "total_pages": len(self.nodes),
            "crawled": sum(1 for n in self.nodes.values() if n.crawl_status == "crawled"),
            "errors": sum(1 for n in self.nodes.values() if n.crawl_status == "error"),
            "status_codes": statuses,
        }

    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "stats": self.stats(),
            "nodes": {pid: n.to_dict() for pid, n in self.nodes.items()},
        }

    def duplicates(self) -> dict[str, list[str]]:
        """Find pages with identical content (by fingerprint)."""
        fp_map: dict[str, list[str]] = {}
        for n in self.nodes.values():
            if n.content_fingerprint:
                fp_map.setdefault(n.content_fingerprint, []).append(n.page_id)
        return {fp: ids for fp, ids in fp_map.items() if len(ids) > 1}

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def load(path: str) -> "WebsiteGraph":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        g = WebsiteGraph(origin=data.get("origin", ""))
        for pid, nd in data.get("nodes", {}).items():
            node = PageNode(
                page_id=nd["page_id"], original_url=nd["original_url"],
                normalized_url=nd["normalized_url"], http_status=nd.get("http_status", 0),
                redirect_chain=nd.get("redirect_chain", []), title=nd.get("title", ""),
                content_type=nd.get("content_type", ""), response_size=nd.get("response_size", 0),
                crawl_depth=nd.get("crawl_depth", 0), parent_id=nd.get("parent_id", ""),
                incoming_links=nd.get("incoming_links", []),
                outgoing_links=nd.get("outgoing_links", []),
                canonical_url=nd.get("canonical_url", ""),
                content_fingerprint=nd.get("content_fingerprint", ""),
                discovery_timestamp=nd.get("discovery_timestamp", ""),
                crawl_status=nd.get("crawl_status", "pending"), error=nd.get("error", ""),
                body_sample=nd.get("body_sample", "")[:BODY_SAMPLE_MAX],
            )
            g.nodes[pid] = node
            g.url_to_id[node.normalized_url] = pid
        g._id_counter = len(g.nodes)
        return g


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------

def _fetch_robots(origin: str, timeout: int = 10) -> urllib.robotparser.RobotFileParser:
    rp = urllib.robotparser.RobotFileParser()
    robots_url = urllib.parse.urljoin(origin, "/robots.txt")
    rp.set_url(robots_url)
    try:
        rp.read()
    except Exception:
        rp.allow_all = True
    return rp


# ---------------------------------------------------------------------------
# Crawl configuration
# ---------------------------------------------------------------------------

@dataclass
class CrawlConfig:
    start_url: str = ""
    max_depth: int = DEFAULT_MAX_DEPTH
    max_pages: int = DEFAULT_MAX_PAGES
    timeout: int = DEFAULT_TIMEOUT
    delay: float = DEFAULT_DELAY
    max_response_size: int = DEFAULT_MAX_RESPONSE
    allow_subdomains: bool = False
    respect_robots: bool = True
    scope_guard: Any = None
    on_progress: Callable | None = None  # callback(crawled, queued, total)


# ---------------------------------------------------------------------------
# Crawl state (supports pause/resume/cancel)
# ---------------------------------------------------------------------------

@dataclass
class CrawlState:
    running: bool = False
    paused: bool = False
    cancelled: bool = False
    pages_crawled: int = 0
    pages_queued: int = 0
    start_time: str = ""
    errors: list[str] = field(default_factory=list)
    _pause_event: threading.Event = field(default_factory=lambda: threading.Event())
    _cancel_event: threading.Event = field(default_factory=lambda: threading.Event())

    def __post_init__(self):
        self._pause_event.set()

    def pause(self):
        self.paused = True
        self._pause_event.clear()

    def resume(self):
        self.paused = False
        self._pause_event.set()

    def cancel(self):
        self.cancelled = True
        self._cancel_event.set()
        self._pause_event.set()

    def wait_if_paused(self, timeout: float | None = None) -> bool:
        """Block while paused. Returns False if cancelled.
        `timeout` None = wait indefinitely until resumed/cancelled; a float
        value polls so callers that want to be responsive can re-check."""
        while not self._pause_event.is_set() and not self.cancelled:
            # cancel also sets the pause event, so waking means one of them
            woke = self._pause_event.wait(timeout if timeout is not None else 0.5)
            if timeout is not None and not woke:
                break  # bounded wait expired
        return not self.cancelled


# ---------------------------------------------------------------------------
# Scope validation for crawling
# ---------------------------------------------------------------------------

def validate_crawl_target(url: str, scope_guard: Any = None) -> tuple[bool, str]:
    """Check that a URL is safe to crawl (not SSRF, in scope, valid scheme).

    Note: this is a pre-flight check; the actual fetch re-resolves and pins
    the IP it will connect to via _resolve_and_pin, closing the DNS-rebinding
    TOCTOU gap that would otherwise exist between here and _fetch_page."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        return False, f"unsupported scheme: {p.scheme}"
    host = (p.hostname or "").lower()
    if not host:
        return False, "empty hostname"
    if _is_blocked_host(host, scope_guard):
        return False, f"blocked host: {host} (loopback/metadata/private)"
    port = p.port or (443 if p.scheme == "https" else 80)
    ok, reason, _ip = _resolve_and_pin(host, port, scope_guard)
    if not ok:
        # If DNS failed entirely, let the fetch stage try — the pinned fetch
        # will fail-closed with the same check. Only reject here if the host
        # actually resolves to a blocked address.
        if "blocked" in reason or "rebinding" in reason:
            return False, reason
    # scope guard check
    if scope_guard:
        ok, reason = scope_guard.check(host)
        if not ok:
            try:
                ip = socket.gethostbyname(host)
                ok, reason = scope_guard.check(ip)
            except socket.gaierror:
                pass
        if not ok:
            return False, f"out of scope: {host} — {reason}"
    return True, "ok"


def validate_redirect(redirect_url: str, origin: str,
                      allow_subdomains: bool = False,
                      scope_guard: Any = None) -> tuple[bool, str]:
    """Validate a redirect destination against scope."""
    if not same_domain(redirect_url, origin, allow_subdomains):
        return False, f"redirect leaves origin: {redirect_url}"
    return validate_crawl_target(redirect_url, scope_guard)


# ---------------------------------------------------------------------------
# HTTP fetcher (follows redirects manually for chain tracking)
# ---------------------------------------------------------------------------

def _fetch_page(url: str, config: CrawlConfig) -> tuple[int, str, dict, list[str], str]:
    """Fetch a URL, return (status, body, headers, redirect_chain, final_url).

    Pins the connection to a validated IP (no second DNS lookup between
    validate and connect), keeps TLS SNI/verification on the original
    hostname, and re-validates every redirect destination the same way.
    Follows redirects manually so the chain is observable."""
    import http.client

    redirect_chain: list[str] = []
    current = url
    max_redirects = 10

    for _ in range(max_redirects):
        p = urllib.parse.urlparse(current)
        hostname = (p.hostname or "").lower()
        if not hostname or p.scheme not in ("http", "https"):
            return 0, "", {}, redirect_chain, current
        port = p.port or (443 if p.scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path = f"{path}?{p.query}"

        # Resolve once, pin that IP. Rebinding guard runs inside.
        ok, reason, pinned_ip = _resolve_and_pin(hostname, port, config.scope_guard)
        if not ok:
            return 0, "", {}, redirect_chain, current

        conn: http.client.HTTPConnection | None = None
        sock = None
        try:
            # Connect by IP, not by hostname — the IP cannot change under us.
            sock = socket.create_connection((pinned_ip, port), timeout=config.timeout)
            if p.scheme == "https":
                ssl_ctx = ssl.create_default_context()
                # SNI + cert check against the real hostname, over the pinned socket
                sock = ssl_ctx.wrap_socket(sock, server_hostname=hostname)
                conn = http.client.HTTPSConnection(hostname, port, timeout=config.timeout)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=config.timeout)
            # Pre-set the socket so conn.request() does not reconnect by name.
            conn.sock = sock
            conn.request("GET", path, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Host": hostname if port in (80, 443) else f"{hostname}:{port}",
            })
            resp = conn.getresponse()
            status = resp.status
            headers = {k: v for k, v in resp.getheaders()}

            if status in (301, 302, 303, 307, 308):
                location = headers.get("Location") or headers.get("location") or ""
                try:
                    resp.read()  # drain
                except Exception:
                    pass
                if not location:
                    return status, "", headers, redirect_chain, current
                redirect_chain.append(current)
                new_url = normalize_url(location, current)
                if not new_url:
                    return status, "", headers, redirect_chain, current
                # Same-origin check up front, then the loop re-resolves and
                # re-pins the destination (so a redirect cannot escape into
                # metadata/private space either).
                if not same_domain(new_url, config.start_url, config.allow_subdomains):
                    return status, "", headers, redirect_chain, current
                current = new_url
                continue

            ct = headers.get("Content-Type") or headers.get("content-type") or ""
            mime = ct.split(";")[0].strip().lower()
            if mime not in CONTENT_TYPES:
                try:
                    resp.read(1)
                except Exception:
                    pass
                return status, "", headers, redirect_chain, current

            body_bytes = resp.read(config.max_response_size + 1)
            if len(body_bytes) > config.max_response_size:
                return status, "", headers, redirect_chain, current
            charset = "utf-8"
            if "charset=" in ct:
                charset = ct.split("charset=")[-1].strip().split(";")[0].strip()
            try:
                body = body_bytes.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                body = body_bytes.decode("utf-8", errors="replace")
            return status, body, headers, redirect_chain, current
        except (socket.timeout, OSError, ssl.SSLError,
                http.client.HTTPException):
            return 0, "", {}, redirect_chain, current
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

    return 0, "", {}, redirect_chain, current


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl(config: CrawlConfig) -> tuple[WebsiteGraph, CrawlState]:
    """Crawl a website and return its graph and final state."""
    state = CrawlState(
        running=True,
        start_time=datetime.datetime.now().isoformat(timespec="seconds"),
    )

    # Validate start URL
    ok, reason = validate_crawl_target(config.start_url, config.scope_guard)
    if not ok:
        state.running = False
        state.errors.append(f"start URL rejected: {reason}")
        return WebsiteGraph(origin=config.start_url), state

    norm_start = normalize_url(config.start_url)
    if not norm_start:
        state.running = False
        state.errors.append("invalid start URL")
        return WebsiteGraph(origin=config.start_url), state

    graph = WebsiteGraph(origin=norm_start)

    # robots.txt
    rp = None
    if config.respect_robots:
        rp = _fetch_robots(norm_start, config.timeout)

    # BFS queue: (url, depth, parent_id)
    queue: deque[tuple[str, int, str]] = deque()
    root = graph.add_node(config.start_url, depth=0)
    queue.append((norm_start, 0, root.page_id))
    visited: set[str] = set()

    while queue and not state.cancelled:
        if not state.wait_if_paused():
            break

        if state.pages_crawled >= config.max_pages:
            break

        url, depth, parent_id = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        node = graph.get_by_url(url)
        if node is None:
            node = graph.add_node(url, depth=depth, parent_id=parent_id)

        # depth check
        if depth > config.max_depth:
            node.crawl_status = "skipped"
            continue

        # robots check
        if rp and not rp.can_fetch(USER_AGENT, url):
            node.crawl_status = "skipped"
            node.error = "blocked by robots.txt"
            continue

        # scope check for every URL
        ok, reason = validate_crawl_target(url, config.scope_guard)
        if not ok:
            node.crawl_status = "skipped"
            node.error = reason
            continue

        # delay
        if config.delay > 0 and state.pages_crawled > 0:
            time.sleep(config.delay)

        # fetch
        status, body, headers, redirect_chain, final_url = _fetch_page(url, config)
        node.http_status = status
        node.redirect_chain = redirect_chain
        node.content_type = headers.get("Content-Type", "").split(";")[0].strip()
        node.headers = {k: v for k, v in headers.items()
                        if k.lower() in ("server", "x-powered-by", "content-type",
                                          "x-frame-options", "content-security-policy",
                                          "strict-transport-security")}

        if status == 0:
            node.crawl_status = "error"
            node.error = "connection failed"
            state.errors.append(f"{url}: connection failed")
            continue

        if status >= 400:
            node.crawl_status = "crawled"
            state.pages_crawled += 1
            continue

        if not body:
            node.crawl_status = "crawled"
            state.pages_crawled += 1
            continue

        # parse
        node.response_size = len(body.encode("utf-8", errors="replace"))
        node.content_fingerprint = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
        links, title, canonical = extract_links(body, final_url)
        node.title = title
        node.canonical_url = canonical
        # Keep a bounded sample of the HTML body for later analysis
        # (web_analysis AUTH/FILE/SEARCH signals need the actual body).
        node.body_sample = body[:BODY_SAMPLE_MAX]
        node.crawl_status = "crawled"
        state.pages_crawled += 1

        # enqueue discovered links
        for link in links:
            if not same_domain(link, config.start_url, config.allow_subdomains):
                continue
            if link not in visited and graph.get_by_url(link) is None:
                child = graph.add_node(link, depth=depth + 1, parent_id=node.page_id)
                queue.append((child.normalized_url, depth + 1, node.page_id))
                state.pages_queued += 1
            # record edge
            target_node = graph.get_by_url(link)
            if target_node:
                graph.add_edge(node.page_id, target_node.page_id)

        # progress callback
        if config.on_progress:
            try:
                config.on_progress(state.pages_crawled, len(queue), len(graph.nodes))
            except Exception:
                pass

    state.running = False
    return graph, state


# ---------------------------------------------------------------------------
# CLI integration helpers
# ---------------------------------------------------------------------------

def format_crawl_summary(graph: WebsiteGraph, state: CrawlState) -> str:
    s = graph.stats()
    lines = [
        f"  Crawl complete: {s['total_pages']} pages discovered, {s['crawled']} crawled",
        f"  Errors: {s['errors']}",
    ]
    if s["status_codes"]:
        codes = ", ".join(f"{k}:{v}" for k, v in sorted(s["status_codes"].items()))
        lines.append(f"  Status codes: {codes}")
    dupes = graph.duplicates()
    if dupes:
        lines.append(f"  Duplicate content groups: {len(dupes)}")
    if state.errors:
        lines.append(f"  Error details: {'; '.join(state.errors[:5])}")
    return "\n".join(lines)


def format_page_detail(node: PageNode) -> str:
    lines = [
        f"  Page: {node.page_id}",
        f"  URL: {node.original_url}",
        f"  Normalized: {node.normalized_url}",
        f"  Status: {node.http_status}",
        f"  Title: {node.title or '(none)'}",
        f"  Content-Type: {node.content_type}",
        f"  Size: {node.response_size} bytes",
        f"  Depth: {node.crawl_depth}",
        f"  Crawl status: {node.crawl_status}",
    ]
    if node.redirect_chain:
        lines.append(f"  Redirects: {' -> '.join(node.redirect_chain)}")
    if node.canonical_url:
        lines.append(f"  Canonical: {node.canonical_url}")
    if node.content_fingerprint:
        lines.append(f"  Fingerprint: {node.content_fingerprint}")
    if node.incoming_links:
        lines.append(f"  Incoming: {len(node.incoming_links)} links")
    if node.outgoing_links:
        lines.append(f"  Outgoing: {len(node.outgoing_links)} links")
    if node.headers:
        for k, v in node.headers.items():
            lines.append(f"  Header {k}: {v}")
    if node.error:
        lines.append(f"  Error: {node.error}")
    return "\n".join(lines)
