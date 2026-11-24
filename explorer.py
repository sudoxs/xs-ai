#!/usr/bin/env python3
"""
xs-ai explorer — optional web interface for browsing crawled website graphs.

Serves a lightweight interactive HTML page on localhost. Does not break the
existing CLI — this is an optional add-on started with :explore or --explore.
Pure stdlib; no external dependencies.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
import urllib.parse
from typing import Any

DEFAULT_PORT = 8477

# The HTML/JS/CSS is embedded as a string to keep the project single-file.
# It renders a force-directed graph with filtering, search, and page detail.

_EXPLORER_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XS-AI Website Explorer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0d0b;--surface:#111611;--border:#232a23;--ink:#c2c8c1;
  --ink-dim:#7a837a;--ink-bright:#e8ebe5;--danger:#cf4a50;--signal:#93a886;
  --amber:#a88747;--mono:"Cascadia Code",Consolas,monospace}
body{background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;
  display:flex;height:100vh;overflow:hidden}
#sidebar{width:340px;border-right:1px solid var(--border);display:flex;
  flex-direction:column;background:var(--surface)}
#sidebar h1{padding:12px 16px;font-size:14px;color:var(--ink-bright);
  border-bottom:1px solid var(--border);letter-spacing:.1em}
#controls{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;
  flex-direction:column;gap:6px}
#controls input,#controls select{background:var(--bg);border:1px solid var(--border);
  color:var(--ink);padding:4px 8px;font-family:var(--mono);font-size:12px;
  border-radius:3px}
#controls input:focus,#controls select:focus{outline:1px solid var(--signal);
  border-color:var(--signal)}
.filter-row{display:flex;gap:6px}
.filter-row select{flex:1}
#stats{padding:6px 12px;font-size:11px;color:var(--ink-dim);
  border-bottom:1px solid var(--border)}
#page-list{flex:1;overflow-y:auto;padding:4px 0}
.page-item{padding:6px 12px;cursor:pointer;border-left:3px solid transparent;
  transition:background .15s}
.page-item:hover{background:rgba(147,168,134,.08)}
.page-item.selected{background:rgba(147,168,134,.12);border-left-color:var(--signal)}
.page-item .url{font-size:11px;color:var(--ink);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
.page-item .meta{font-size:10px;color:var(--ink-dim);margin-top:2px}
.status-2xx{color:var(--signal)}.status-3xx{color:var(--amber)}
.status-4xx{color:var(--danger)}.status-5xx{color:#ff6b6b}
.status-0{color:var(--ink-dim)}
#main{flex:1;display:flex;flex-direction:column}
#graph-container{flex:1;position:relative;background:var(--bg)}
canvas{width:100%;height:100%}
#detail{height:280px;border-top:1px solid var(--border);overflow-y:auto;
  padding:12px 16px;background:var(--surface)}
#detail h2{font-size:12px;color:var(--signal);margin-bottom:8px;letter-spacing:.08em}
#detail .row{display:flex;margin-bottom:4px}
#detail .label{width:120px;color:var(--ink-dim);flex-shrink:0;font-size:11px}
#detail .value{color:var(--ink);font-size:11px;word-break:break-all}
#detail .link-list{margin-top:8px}
#detail .link-list h3{font-size:11px;color:var(--amber);margin-bottom:4px}
#detail .link-list a{color:var(--signal);font-size:11px;text-decoration:none;
  display:block;padding:1px 0}
#detail .link-list a:hover{text-decoration:underline}
#progress{position:absolute;top:8px;right:8px;background:rgba(17,22,17,.9);
  padding:6px 12px;border:1px solid var(--border);border-radius:4px;
  font-size:11px;color:var(--ink-dim);display:none}
</style>
</head>
<body>
<div id="sidebar">
  <h1>XS-AI EXPLORER</h1>
  <div id="controls">
    <input type="text" id="search" placeholder="Search URLs..." autocomplete="off">
    <div class="filter-row">
      <select id="filter-status"><option value="">All status</option>
        <option value="2">2xx</option><option value="3">3xx</option>
        <option value="4">4xx</option><option value="5">5xx</option>
        <option value="0">Error</option></select>
      <select id="filter-depth"><option value="">All depths</option></select>
      <select id="filter-type"><option value="">All types</option></select>
    </div>
  </div>
  <div id="stats"></div>
  <div id="page-list"></div>
</div>
<div id="main">
  <div id="graph-container">
    <canvas id="canvas"></canvas>
    <div id="progress"></div>
  </div>
  <div id="detail">
    <h2>SELECT A PAGE</h2>
    <p style="color:var(--ink-dim);font-size:11px">Click a page in the list or graph to inspect it.</p>
  </div>
</div>

<script>
let graphData = null;
let nodes = [];
let selectedId = null;

async function loadGraph() {
  const resp = await fetch('/api/graph');
  graphData = await resp.json();
  nodes = Object.values(graphData.nodes || {});
  buildFilters();
  renderList();
  renderStats();
  drawGraph();
}

function buildFilters() {
  const depths = new Set(nodes.map(n => n.crawl_depth));
  const ds = document.getElementById('filter-depth');
  [...depths].sort((a,b)=>a-b).forEach(d => {
    const o = document.createElement('option'); o.value=d; o.textContent='Depth '+d; ds.appendChild(o);
  });
  const types = new Set(nodes.map(n => n.content_type).filter(Boolean));
  const ts = document.getElementById('filter-type');
  types.forEach(t => {
    const o = document.createElement('option'); o.value=t; o.textContent=t; ts.appendChild(o);
  });
}

function getFiltered() {
  const q = document.getElementById('search').value.toLowerCase();
  const st = document.getElementById('filter-status').value;
  const dp = document.getElementById('filter-depth').value;
  const ct = document.getElementById('filter-type').value;
  return nodes.filter(n => {
    if (q && !n.normalized_url.toLowerCase().includes(q) && !(n.title||'').toLowerCase().includes(q)) return false;
    if (st && !String(n.http_status).startsWith(st)) return false;
    if (dp !== '' && n.crawl_depth !== parseInt(dp)) return false;
    if (ct && n.content_type !== ct) return false;
    return true;
  });
}

function statusClass(s) {
  if (s >= 200 && s < 300) return 'status-2xx';
  if (s >= 300 && s < 400) return 'status-3xx';
  if (s >= 400 && s < 500) return 'status-4xx';
  if (s >= 500) return 'status-5xx';
  return 'status-0';
}

function renderList() {
  const list = document.getElementById('page-list');
  const filtered = getFiltered();
  list.innerHTML = filtered.map(n => `
    <div class="page-item ${n.page_id===selectedId?'selected':''}" data-id="${n.page_id}">
      <div class="url">${escHtml(n.normalized_url)}</div>
      <div class="meta"><span class="${statusClass(n.http_status)}">${n.http_status||'ERR'}</span>
        &middot; d${n.crawl_depth} &middot; ${n.title ? escHtml(n.title.slice(0,40)) : '(no title)'}</div>
    </div>
  `).join('');
  list.querySelectorAll('.page-item').forEach(el => {
    el.addEventListener('click', () => selectPage(el.dataset.id));
  });
}

function renderStats() {
  const s = graphData.stats || {};
  document.getElementById('stats').textContent =
    `${s.total_pages||0} pages | ${s.crawled||0} crawled | ${s.errors||0} errors`;
}

function selectPage(id) {
  selectedId = id;
  const n = graphData.nodes[id];
  if (!n) return;
  renderList();
  const d = document.getElementById('detail');
  const rows = [
    ['Page ID', n.page_id], ['URL', n.original_url], ['Normalized', n.normalized_url],
    ['Status', n.http_status], ['Title', n.title||'(none)'], ['Type', n.content_type],
    ['Size', n.response_size+' bytes'], ['Depth', n.crawl_depth],
    ['Crawl status', n.crawl_status], ['Fingerprint', n.content_fingerprint||'—'],
    ['Canonical', n.canonical_url||'—'], ['Discovered', n.discovery_timestamp],
  ];
  if (n.redirect_chain && n.redirect_chain.length)
    rows.push(['Redirects', n.redirect_chain.join(' → ')]);
  if (n.error) rows.push(['Error', n.error]);

  let html = `<h2>PAGE DETAIL</h2>`;
  rows.forEach(([l,v]) => { html += `<div class="row"><span class="label">${l}</span><span class="value">${escHtml(String(v))}</span></div>`; });

  if (n.incoming_links && n.incoming_links.length) {
    html += `<div class="link-list"><h3>Incoming (${n.incoming_links.length})</h3>`;
    n.incoming_links.forEach(lid => {
      const ln = graphData.nodes[lid];
      if (ln) html += `<a href="#" data-id="${lid}">${escHtml(ln.normalized_url)}</a>`;
    });
    html += `</div>`;
  }
  if (n.outgoing_links && n.outgoing_links.length) {
    html += `<div class="link-list"><h3>Outgoing (${n.outgoing_links.length})</h3>`;
    n.outgoing_links.forEach(lid => {
      const ln = graphData.nodes[lid];
      if (ln) html += `<a href="#" data-id="${lid}">${escHtml(ln.normalized_url)}</a>`;
    });
    html += `</div>`;
  }
  d.innerHTML = html;
  d.querySelectorAll('.link-list a').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); selectPage(a.dataset.id); });
  });
  drawGraph();
}

function escHtml(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

// Simple force-directed graph on canvas
function drawGraph() {
  const canvas = document.getElementById('canvas');
  const container = document.getElementById('graph-container');
  canvas.width = container.clientWidth;
  canvas.height = container.clientHeight;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  if (nodes.length === 0) return;
  if (nodes.length > 200) {
    ctx.fillStyle = '#7a837a'; ctx.font = '12px monospace';
    ctx.fillText(`${nodes.length} nodes — showing list view only (graph disabled for large sites)`, 20, 30);
    return;
  }

  // layout: simple radial by depth
  const byDepth = {};
  nodes.forEach(n => { (byDepth[n.crawl_depth] = byDepth[n.crawl_depth]||[]).push(n); });
  const positions = {};
  const depths = Object.keys(byDepth).map(Number).sort((a,b)=>a-b);
  const maxR = Math.min(W, H) * 0.42;
  depths.forEach(d => {
    const group = byDepth[d];
    const r = (d / (depths.length || 1)) * maxR + 30;
    group.forEach((n, i) => {
      const angle = (i / group.length) * Math.PI * 2 - Math.PI / 2;
      positions[n.page_id] = { x: W/2 + r * Math.cos(angle), y: H/2 + r * Math.sin(angle) };
    });
  });

  // draw edges
  ctx.strokeStyle = 'rgba(74,91,65,.2)'; ctx.lineWidth = 0.5;
  nodes.forEach(n => {
    const from = positions[n.page_id];
    if (!from) return;
    (n.outgoing_links||[]).forEach(tid => {
      const to = positions[tid];
      if (!to) return;
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y); ctx.stroke();
    });
  });

  // draw nodes
  nodes.forEach(n => {
    const p = positions[n.page_id];
    if (!p) return;
    const isSel = n.page_id === selectedId;
    const r = isSel ? 6 : 3;
    ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI*2);
    if (isSel) { ctx.fillStyle = '#cf4a50'; }
    else if (n.http_status >= 200 && n.http_status < 300) { ctx.fillStyle = '#93a886'; }
    else if (n.http_status >= 300 && n.http_status < 400) { ctx.fillStyle = '#a88747'; }
    else if (n.http_status >= 400) { ctx.fillStyle = '#cf4a50'; }
    else { ctx.fillStyle = '#4a534b'; }
    ctx.fill();
    if (isSel) {
      ctx.font = '10px monospace'; ctx.fillStyle = '#e8ebe5';
      const label = n.title || new URL(n.normalized_url).pathname;
      ctx.fillText(label.slice(0,40), p.x+8, p.y+4);
    }
  });

  // click handler
  canvas.onclick = function(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let closest = null, minD = 20;
    nodes.forEach(n => {
      const p = positions[n.page_id]; if (!p) return;
      const d = Math.hypot(p.x-mx, p.y-my);
      if (d < minD) { minD = d; closest = n.page_id; }
    });
    if (closest) selectPage(closest);
  };
}

// filters
document.getElementById('search').addEventListener('input', renderList);
document.getElementById('filter-status').addEventListener('change', renderList);
document.getElementById('filter-depth').addEventListener('change', renderList);
document.getElementById('filter-type').addEventListener('change', renderList);
window.addEventListener('resize', drawGraph);

loadGraph();
</script>
</body>
</html>"""


class _ExplorerHandler(http.server.BaseHTTPRequestHandler):
    graph_data: dict = {}

    def log_message(self, format, *args):
        pass  # silence HTTP logs

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/graph":
            body = json.dumps(self.graph_data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/" or path == "/index.html":
            body = _EXPLORER_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)


def start_explorer(graph_data: dict, port: int = DEFAULT_PORT,
                   background: bool = True) -> tuple[socketserver.TCPServer | None, str]:
    """Start the explorer web UI on localhost. Returns (server, url)."""
    _ExplorerHandler.graph_data = graph_data

    try:
        server = socketserver.TCPServer(("127.0.0.1", port), _ExplorerHandler)
    except OSError:
        return None, f"port {port} in use"

    url = f"http://127.0.0.1:{port}"
    if background:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
    return server, url


def stop_explorer(server: socketserver.TCPServer | None) -> None:
    if server:
        server.shutdown()
