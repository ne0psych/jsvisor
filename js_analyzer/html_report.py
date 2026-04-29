#!/usr/bin/env python3
"""
Enhancement #6 — Enhanced HTML Report Generator

- Client-side search/filter
- Copy to clipboard button per finding
- Improved responsive design
- Framework and CDN summary sections
"""

import datetime
import json
from pathlib import Path
from collections import defaultdict

CAT_META = {
    "endpoints":  ("Endpoints",       "#4fc1ff", "Routes and API paths discovered in the source."),
    "urls":       ("URLs",            "#79c0ff", "Absolute URLs to external or internal services."),
    "secrets":    ("Secrets",         "#ff7b72", "Potential credentials, tokens, and API keys."),
    "emails":     ("Emails",          "#ffa657", "Email addresses embedded in the code."),
    "files":      ("Files",           "#7ee787", "References to sensitive or interesting file types."),
    "sourcemaps": ("Source Maps",     "#d2a8ff", "Source map references that may expose original code."),
    "cloud":      ("Cloud Resources", "#56d364", "Cloud infrastructure identifiers (ARNs, buckets, etc.)."),
    "debug":      ("Debug Artifacts", "#e3b341", "Debug statements, TODO/FIXME comments, env references."),
    "graphql":    ("GraphQL",         "#bc8cff", "GraphQL operation names found in the source."),
    "network":    ("Internal Network","#f85149", "Private IPs and internal hostnames."),
    "wasm":       ("WebAssembly",     "#ff9ff3", "WebAssembly usage and exports."),
    "storage":    ("Browser Storage", "#48dbfb", "localStorage/sessionStorage/IndexedDB keys."),
    "cors":       ("CORS Issues",     "#ff6b6b", "CORS misconfiguration findings."),
    "frameworks": ("Frameworks",      "#a29bfe", "Framework-specific endpoints and patterns."),
}


def _esc(s: str) -> str:
    """HTML-escape a string."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_html_report(findings: dict, meta: dict) -> str:
    """Render enhanced self-contained HTML report with search, filter, and copy."""
    scan_time    = meta.get("scan_time", datetime.datetime.now().isoformat(timespec="seconds"))
    target       = meta.get("target", "Unknown")
    file_count   = meta.get("file_count", 1)
    total        = sum(len(v) for v in findings.values())
    secret_count = len(findings.get("secrets", []))
    frameworks   = meta.get("frameworks", [])
    cdn_summary  = meta.get("cdn_summary", {})

    # Build sidebar nav items
    sidebar_items = ""
    for cat, items in findings.items():
        n = len(items)
        if n == 0:
            continue
        label, color, _ = CAT_META.get(cat, (cat.title(), "#ccc", ""))
        badge_cls = "badge-danger" if cat == "secrets" and n else "badge"
        sidebar_items += (
            f'<li><a href="#cat-{cat}" class="nav-link" onclick="showCat(\'{cat}\')">'
            f'<span class="nav-dot" style="background:{color}"></span>'
            f'{label}'
            f'<span class="{badge_cls}">{n}</span>'
            f'</a></li>\n'
        )

    # Build summary cards
    cards = ""
    for cat, items in findings.items():
        n = len(items)
        if not n:
            continue
        label, color, desc = CAT_META.get(cat, (cat.title(), "#ccc", ""))
        cards += f'''
        <div class="summary-card" onclick="showCat('{cat}')" style="border-top:3px solid {color}">
          <div class="card-count" style="color:{color}">{n}</div>
          <div class="card-label">{label}</div>
          <div class="card-desc">{desc}</div>
        </div>'''

    # Build framework badges
    fw_html = ""
    if frameworks:
        fw_badges = " ".join(f'<span class="fw-badge">{fw}</span>' for fw in frameworks)
        fw_html = f'<div class="fw-section"><strong>Frameworks detected:</strong> {fw_badges}</div>'

    # Build CDN summary
    cdn_html = ""
    if cdn_summary:
        cdn_items = " ".join(
            f'<span class="cdn-badge">{p} ({d["count"]})</span>'
            for p, d in cdn_summary.items()
        )
        cdn_html = f'<div class="cdn-section"><strong>CDN/Cloud providers:</strong> {cdn_items}</div>'

    # Build per-category sections
    sections = ""
    for cat, items in findings.items():
        if not items:
            continue
        label, color, desc = CAT_META.get(cat, (cat.title(), "#ccc", ""))

        by_file = defaultdict(list)
        for item in items:
            by_file[item.get("source", "<unknown>")].append(item)

        rows_html = ""
        for src, src_items in sorted(by_file.items()):
            file_label = Path(src).name if src != "<unknown>" else src
            rows_html += f'''
            <tr class="file-row">
              <td colspan="4" class="file-header" title="{_esc(src)}">
                <span class="file-icon">F</span> {_esc(file_label)}
                <span class="file-count">{len(src_items)} finding(s)</span>
              </td>
            </tr>'''
            for item in src_items:
                ln = item.get("line", "?")
                val = _esc(item["value"])
                raw_val = item["value"].replace("'", "\\'").replace('"', '\\"')
                sev_cls = "sev-high" if cat == "secrets" else ("sev-med" if cat in ("network", "cloud", "cors") else "sev-low")
                conf = item.get("confidence", "")
                conf_badge = f' <span class="conf-{conf}">[{conf}]</span>' if conf else ""
                rows_html += f'''
            <tr class="finding-row {sev_cls}" data-value="{val}" data-source="{_esc(src)}" data-line="{ln}">
              <td class="ln-col">{ln}</td>
              <td class="val-col"><code>{val}</code>{conf_badge}</td>
              <td class="sev-col"><span class="sev-badge {sev_cls}-badge">{cat.upper()}</span></td>
              <td class="copy-col"><button class="copy-btn" onclick="copyVal('{raw_val}')" title="Copy to clipboard">📋</button></td>
            </tr>'''

        sections += f'''
      <section id="cat-{cat}" class="cat-section" style="display:none">
        <div class="section-header" style="border-left:4px solid {color}">
          <h2>{label}</h2>
          <p class="section-desc">{desc}</p>
          <div class="section-stats">{len(items)} finding(s) across {len(by_file)} file(s)</div>
        </div>
        <div class="table-wrap">
          <table class="findings-table">
            <thead>
              <tr>
                <th class="ln-col">Line</th>
                <th>Value</th>
                <th class="sev-col">Category</th>
                <th class="copy-col">Copy</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
      </section>'''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JS Analyzer Report</title>
<style>
:root {{
  --bg: #0d1117; --surface: #161b22; --surface2: #1c2128;
  --border: #30363d; --text: #e6edf3; --muted: #8b949e;
  --accent: #388bfd; --danger: #f85149; --warn: #e3b341; --ok: #3fb950;
  --radius: 6px; --sidebar-w: 240px;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; font-size:14px; display:flex; min-height:100vh; }}

/* Sidebar */
.sidebar {{ width: var(--sidebar-w); min-height: 100vh; background: var(--surface); border-right:1px solid var(--border); position:fixed; top:0;left:0;bottom:0; display:flex; flex-direction:column; overflow-y:auto; z-index:10; }}
.sidebar-logo {{ padding:20px 16px 12px; border-bottom:1px solid var(--border); }}
.sidebar-logo h1 {{ font-size:16px; font-weight:700; color:var(--text); letter-spacing:.5px; }}
.sidebar-logo .sub {{ font-size:11px; color:var(--muted); margin-top:3px; }}
.nav-section {{ padding:12px 0; }}
.nav-section-label {{ font-size:11px; font-weight:600; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; padding:0 16px 6px; }}
.nav-link {{ display:flex; align-items:center; gap:8px; padding:7px 16px; color:var(--muted); text-decoration:none; cursor:pointer; transition:background .15s,color .15s; font-size:13px; }}
.nav-link:hover, .nav-link.active {{ background:var(--surface2); color:var(--text); }}
.nav-dot {{ width:8px; height:8px; border-radius:50%; flex-shrink:0; }}
.badge, .badge-danger {{ margin-left:auto; font-size:11px; font-weight:600; padding:1px 6px; border-radius:10px; }}
.badge {{ background:#21262d; color:var(--muted); }}
.badge-danger {{ background:#3d1f20; color:var(--danger); }}
.nav-overview {{ font-weight:600; color:var(--text) !important; }}
.sidebar-footer {{ padding:12px 16px; border-top:1px solid var(--border); font-size:11px; color:var(--muted); margin-top:auto; }}

/* Main */
.main {{ margin-left:var(--sidebar-w); flex:1; padding:24px; max-width:1200px; }}

/* Search bar */
.search-bar {{ margin-bottom:16px; display:flex; gap:8px; }}
.search-bar input {{ flex:1; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:8px 12px; color:var(--text); font-size:13px; outline:none; transition:border-color .15s; }}
.search-bar input:focus {{ border-color:var(--accent); }}
.search-bar input::placeholder {{ color:var(--muted); }}

/* Header */
.report-header {{ margin-bottom:24px; padding-bottom:16px; border-bottom:1px solid var(--border); }}
.report-header h2 {{ font-size:20px; font-weight:700; }}
.report-meta {{ display:flex; gap:24px; margin-top:10px; flex-wrap:wrap; }}
.meta-item {{ font-size:12px; color:var(--muted); }}
.meta-item strong {{ color:var(--text); }}
.alert-banner {{ background:#3d1f20; border:1px solid #6e2b2b; border-radius:var(--radius); padding:10px 16px; margin-bottom:20px; display:flex; align-items:center; gap:10px; color:#ff7b72; font-size:13px; font-weight:500; }}
.alert-banner.hidden {{ display:none; }}

/* Framework / CDN badges */
.fw-section, .cdn-section {{ margin-bottom:12px; font-size:13px; }}
.fw-badge, .cdn-badge {{ display:inline-block; background:var(--surface2); border:1px solid var(--border); border-radius:12px; padding:2px 10px; margin:2px; font-size:11px; font-weight:600; text-transform:capitalize; }}

/* Summary cards */
.cards-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin-bottom:28px; }}
.summary-card {{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:14px; cursor:pointer; transition:border-color .15s,background .15s,transform .1s; }}
.summary-card:hover {{ background:var(--surface2); border-color:var(--accent); transform:translateY(-2px); }}
.card-count {{ font-size:28px; font-weight:700; line-height:1; }}
.card-label {{ font-size:12px; font-weight:600; margin-top:4px; }}
.card-desc {{ font-size:11px; color:var(--muted); margin-top:4px; line-height:1.4; }}

/* Sections */
.cat-section {{ animation:fadeIn .15s ease; }}
@keyframes fadeIn {{ from{{opacity:0;transform:translateY(4px)}} to{{opacity:1;transform:none}} }}
.section-header {{ padding:0 0 16px 12px; margin-bottom:16px; border-bottom:1px solid var(--border); }}
.section-header h2 {{ font-size:18px; font-weight:700; }}
.section-desc {{ color:var(--muted); font-size:13px; margin-top:4px; }}
.section-stats {{ font-size:12px; color:var(--accent); margin-top:6px; font-weight:500; }}

/* Table */
.table-wrap {{ overflow-x:auto; border:1px solid var(--border); border-radius:var(--radius); }}
.findings-table {{ width:100%; border-collapse:collapse; font-size:13px; }}
.findings-table th {{ background:var(--surface); color:var(--muted); font-weight:600; text-align:left; padding:8px 12px; font-size:11px; text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border); position:sticky; top:0; }}
.findings-table td {{ padding:7px 12px; border-bottom:1px solid #21262d; vertical-align:middle; }}
.findings-table tr:last-child td {{ border-bottom:none; }}
.findings-table tr.finding-row:hover {{ background:var(--surface); }}
code {{ font-family:'JetBrains Mono','Fira Code',monospace; font-size:12px; word-break:break-all; }}
.ln-col {{ width:60px; color:var(--muted); font-family:monospace; font-size:12px; }}
.sev-col {{ width:110px; }}
.copy-col {{ width:40px; text-align:center; }}
.file-header {{ background:#1c2128; font-size:12px; font-weight:600; color:var(--muted); padding:6px 12px !important; }}
.file-icon {{ display:inline-block; background:#30363d; color:var(--text); font-size:10px; border-radius:3px; padding:0 4px; margin-right:4px; font-weight:700; }}
.file-count {{ float:right; font-weight:400; color:var(--accent); }}
.sev-badge {{ font-size:10px; font-weight:700; padding:2px 6px; border-radius:4px; letter-spacing:.3px; }}
.sev-high-badge  {{ background:#3d1f20; color:#ff7b72; }}
.sev-med-badge   {{ background:#332200; color:#e3b341; }}
.sev-low-badge   {{ background:#1a2632; color:#4fc1ff; }}

/* Copy button */
.copy-btn {{ background:none; border:1px solid var(--border); border-radius:4px; cursor:pointer; padding:2px 6px; font-size:12px; opacity:0.5; transition:opacity .15s; }}
.copy-btn:hover {{ opacity:1; background:var(--surface2); }}

/* Confidence badges */
.conf-high {{ color:#ff7b72; font-size:10px; font-weight:600; }}
.conf-medium {{ color:#e3b341; font-size:10px; font-weight:600; }}
.conf-low {{ color:#8b949e; font-size:10px; font-weight:600; }}

/* Toast notification */
.toast {{ position:fixed; bottom:20px; right:20px; background:#238636; color:white; padding:8px 16px; border-radius:var(--radius); font-size:13px; opacity:0; transition:opacity .3s; z-index:100; }}
.toast.show {{ opacity:1; }}

#overview {{ }}
.overview-section {{ margin-bottom:32px; }}
.overview-title {{ font-size:14px; font-weight:600; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; margin-bottom:12px; }}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-logo">
    <h1>🔍 JS Analyzer</h1>
    <div class="sub">Security Report v4.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-section-label">Navigation</div>
    <ul style="list-style:none">
      <li><a href="#overview" class="nav-link nav-overview active" onclick="showCat('overview')">
        Overview
        <span class="badge">{total}</span>
      </a></li>
    </ul>
  </div>
  <div class="nav-section">
    <div class="nav-section-label">Categories</div>
    <ul style="list-style:none">
      {sidebar_items}
    </ul>
  </div>
  <div class="sidebar-footer">
    Scanned {file_count} file(s)<br>
    {scan_time}
  </div>
</nav>

<main class="main">
  <div class="report-header">
    <h2>Analysis Report</h2>
    <div class="report-meta">
      <div class="meta-item"><strong>Target:</strong> {_esc(target)}</div>
      <div class="meta-item"><strong>Files scanned:</strong> {file_count}</div>
      <div class="meta-item"><strong>Total findings:</strong> {total}</div>
      <div class="meta-item"><strong>Scanned:</strong> {scan_time}</div>
    </div>
  </div>

  <div class="alert-banner {'hidden' if not secret_count else ''}">
    ⚠️ WARNING: {secret_count} potential secret(s) detected. Review immediately.
  </div>

  {fw_html}
  {cdn_html}

  <!-- Search Bar -->
  <div class="search-bar">
    <input type="text" id="search-input" placeholder="🔍 Search findings by value, source, or line..." oninput="filterFindings(this.value)">
  </div>

  <!-- Overview -->
  <div id="overview" class="cat-section">
    <div class="overview-section">
      <div class="overview-title">Summary</div>
      <div class="cards-grid">
        {cards}
      </div>
    </div>
  </div>

  <!-- Per-category sections -->
  {sections}
</main>

<div id="toast" class="toast">Copied to clipboard!</div>

<script>
const navLinks = document.querySelectorAll('.nav-link');
function showCat(cat) {{
  document.querySelectorAll('.cat-section').forEach(s => s.style.display = 'none');
  const el = document.getElementById(cat === 'overview' ? 'overview' : 'cat-' + cat);
  if (el) el.style.display = 'block';
  navLinks.forEach(l => l.classList.remove('active'));
  const active = document.querySelector('.nav-link[onclick*="\\'" + cat + "\\'"]');
  if (active) active.classList.add('active');
}}

function copyVal(text) {{
  navigator.clipboard.writeText(text).then(() => {{
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1500);
  }});
}}

function filterFindings(query) {{
  if (!query) {{
    document.querySelectorAll('.finding-row').forEach(r => r.style.display = '');
    document.querySelectorAll('.file-row').forEach(r => r.style.display = '');
    return;
  }}
  const q = query.toLowerCase();
  document.querySelectorAll('.finding-row').forEach(r => {{
    const val = (r.getAttribute('data-value') || '').toLowerCase();
    const src = (r.getAttribute('data-source') || '').toLowerCase();
    const line = (r.getAttribute('data-line') || '').toLowerCase();
    r.style.display = (val.includes(q) || src.includes(q) || line.includes(q)) ? '' : 'none';
  }});
  // Hide file headers if all their findings are hidden
  document.querySelectorAll('.file-row').forEach(fr => {{
    let next = fr.nextElementSibling;
    let anyVisible = false;
    while (next && !next.classList.contains('file-row')) {{
      if (next.style.display !== 'none') anyVisible = true;
      next = next.nextElementSibling;
    }}
    fr.style.display = anyVisible ? '' : 'none';
  }});
}}

showCat('overview');
</script>
</body>
</html>"""

