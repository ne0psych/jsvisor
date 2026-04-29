"""
HTML Report Generator

Renders a self-contained HTML report with search, filter, collapsible
sections, severity highlighting, and copy-to-clipboard functionality.
All dynamic content is escaped to prevent XSS.
"""

import datetime
import html
import json
from pathlib import Path
from collections import defaultdict

CAT_META = {
    "endpoints":  ("Endpoints",       "#ff4d4d", "Routes and API paths discovered in the source."),
    "urls":       ("URLs",            "#ff6b6b", "Absolute URLs to external or internal services."),
    "secrets":    ("Secrets",         "#ff2d2d", "Potential credentials, tokens, and API keys."),
    "emails":     ("Emails",          "#ff8a65", "Email addresses embedded in the code."),
    "files":      ("Files",           "#66bb6a", "References to sensitive or interesting file types."),
    "sourcemaps": ("Source Maps",     "#ce93d8", "Source map references that may expose original code."),
    "cloud":      ("Cloud Resources", "#4db6ac", "Cloud infrastructure identifiers (ARNs, buckets, etc.)."),
    "debug":      ("Debug Artifacts", "#ffb74d", "Debug statements, TODO/FIXME comments, env references."),
    "graphql":    ("GraphQL",         "#b39ddb", "GraphQL operation names found in the source."),
    "network":    ("Internal Network","#ef5350", "Private IPs and internal hostnames."),
    "wasm":       ("WebAssembly",     "#f48fb1", "WebAssembly usage and exports."),
    "storage":    ("Browser Storage", "#4dd0e1", "localStorage/sessionStorage/IndexedDB keys."),
    "cors":       ("CORS Issues",     "#e57373", "CORS misconfiguration findings."),
    "frameworks": ("Frameworks",      "#9fa8da", "Framework-specific endpoints and patterns."),
}

SEVERITY_ORDER = {
    "secrets": 0, "network": 1, "cors": 2, "cloud": 3,
    "endpoints": 4, "urls": 5, "sourcemaps": 6, "graphql": 7,
    "debug": 8, "emails": 9, "files": 10, "wasm": 11,
    "storage": 12, "frameworks": 13,
}

SEVERITY_LABELS = {
    "secrets": ("CRITICAL", "#ff2d2d"),
    "network": ("HIGH", "#ff4d4d"),
    "cors":    ("HIGH", "#ff4d4d"),
    "cloud":   ("MEDIUM", "#ffb74d"),
    "endpoints": ("MEDIUM", "#ffb74d"),
    "urls":    ("MEDIUM", "#ffb74d"),
    "sourcemaps": ("MEDIUM", "#ffb74d"),
    "graphql": ("MEDIUM", "#ffb74d"),
}


def _esc(s: str) -> str:
    """HTML-escape all dynamic content."""
    return html.escape(str(s), quote=True)


def _js_str(s: str) -> str:
    """Escape for safe embedding in JS string literals."""
    return (s
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("<", "\\x3c")
            .replace(">", "\\x3e"))


def generate_html_report(findings: dict, meta: dict) -> str:
    """Render self-contained HTML security report."""
    scan_time = meta.get("scan_time",
                         datetime.datetime.now().isoformat(timespec="seconds"))
    target = meta.get("target", "Unknown")
    file_count = meta.get("file_count", 1)
    total = sum(len(v) for v in findings.values())
    secret_count = len(findings.get("secrets", []))
    frameworks = meta.get("frameworks", [])
    cdn_summary = meta.get("cdn_summary", {})

    sorted_cats = sorted(
        [(c, v) for c, v in findings.items() if v],
        key=lambda x: SEVERITY_ORDER.get(x[0], 99)
    )

    # Sidebar nav
    sidebar_items = ""
    for cat, items in sorted_cats:
        n = len(items)
        label, color, _ = CAT_META.get(cat, (cat.title(), "#888", ""))
        sev, _ = SEVERITY_LABELS.get(cat, ("LOW", "#888"))
        badge_cls = "sb-crit" if sev == "CRITICAL" else (
            "sb-high" if sev == "HIGH" else "sb-badge")
        sidebar_items += (
            f'<a href="#" class="sb-link" data-cat="{_esc(cat)}">'
            f'<span class="sb-dot" style="background:{color}"></span>'
            f'<span class="sb-label">{_esc(label)}</span>'
            f'<span class="{badge_cls}">{n}</span>'
            f'</a>\n'
        )

    # Summary cards
    cards = ""
    for cat, items in sorted_cats:
        n = len(items)
        label, color, desc = CAT_META.get(cat, (cat.title(), "#888", ""))
        sev, sev_color = SEVERITY_LABELS.get(cat, ("LOW", "#888"))
        cards += (
            f'<div class="s-card" data-cat="{_esc(cat)}">'
            f'<div class="sc-top"><span class="sc-sev" style="color:{sev_color}">{sev}</span></div>'
            f'<div class="sc-num" style="color:{color}">{n}</div>'
            f'<div class="sc-name">{_esc(label)}</div>'
            f'<div class="sc-desc">{_esc(desc)}</div>'
            f'</div>\n'
        )

    # Framework / CDN badges
    fw_html = ""
    if frameworks:
        fw_badges = " ".join(
            f'<span class="pill">{_esc(fw)}</span>' for fw in frameworks)
        fw_html = f'<div class="pill-row"><span class="pill-label">Frameworks</span>{fw_badges}</div>'
    cdn_html = ""
    if cdn_summary:
        cdn_items = " ".join(
            f'<span class="pill">{_esc(p)} ({d["count"]})</span>'
            for p, d in cdn_summary.items())
        cdn_html = f'<div class="pill-row"><span class="pill-label">CDN</span>{cdn_items}</div>'

    # Category detail sections
    sections = ""
    for cat, items in sorted_cats:
        label, color, desc = CAT_META.get(cat, (cat.title(), "#888", ""))
        sev, sev_color = SEVERITY_LABELS.get(cat, ("LOW", "#888"))
        by_file = defaultdict(list)
        for item in items:
            by_file[item.get("source", "<unknown>")].append(item)

        rows = ""
        for src, src_items in sorted(by_file.items()):
            fl = Path(src).name if src != "<unknown>" else src
            rows += (
                f'<tr class="fg-row"><td colspan="4" class="fg-hdr" title="{_esc(src)}">'
                f'<span class="fg-icon">F</span>{_esc(fl)}'
                f'<span class="fg-cnt">{len(src_items)}</span>'
                f'<button class="fg-tog" onclick="tg(this)">&#9660;</button>'
                f'</td></tr>\n'
            )
            for item in src_items:
                ln = item.get("line", "?")
                val = _esc(item["value"])
                js_val = _js_str(item["value"])
                conf = item.get("confidence", "")
                cb = (f' <span class="cf-{_esc(conf)}">[{_esc(conf)}]</span>'
                      if conf else "")
                rows += (
                    f'<tr class="f-row" data-value="{val}" '
                    f'data-source="{_esc(src)}" data-line="{ln}">'
                    f'<td class="c-ln">{ln}</td>'
                    f'<td class="c-val"><code>{val}</code>{cb}</td>'
                    f'<td class="c-sv"><span class="sv-b" '
                    f'style="background:{sev_color}18;color:{sev_color};'
                    f'border:1px solid {sev_color}33">{sev}</span></td>'
                    f'<td class="c-ac"><button class="cp-btn" '
                    f'onclick="cp(\'{js_val}\')">Copy</button></td>'
                    f'</tr>\n'
                )

        sections += (
            f'<section id="cat-{_esc(cat)}" class="cat-sec" style="display:none">'
            f'<div class="sec-hdr"><div class="sec-accent" style="background:{color}"></div>'
            f'<div class="sec-info"><h2>{_esc(label)}</h2>'
            f'<p class="sec-desc">{_esc(desc)}</p>'
            f'<span class="sec-stat">{len(items)} finding(s) in {len(by_file)} file(s)</span>'
            f'</div></div>'
            f'<div class="tbl-wrap"><table class="ftbl">'
            f'<thead><tr><th class="c-ln">Line</th><th>Value</th>'
            f'<th class="c-sv">Severity</th><th class="c-ac"></th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></section>\n'
        )

    alert_cls = "" if secret_count else " hidden"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JSVisor Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root{{
  --bg:#050505;--s1:#0e0e0e;--s2:#161616;--s3:#1e1e1e;
  --bdr:#ffffff0d;--bdr2:#ffffff18;
  --tx:#eaeaea;--tx2:#999;--tx3:#666;
  --red:#ff3333;--red2:#cc2828;--redg:#ff333318;
  --accent:#ff3333;
  --r:12px;
  --sans:'Inter',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','Fira Code',monospace;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{
  background:var(--bg);color:var(--tx);font-family:var(--sans);
  font-size:14px;line-height:1.6;display:flex;min-height:100vh;
}}

/* ── Sidebar ── */
.sb{{
  width:230px;min-height:100vh;background:var(--s1);
  border-right:1px solid var(--bdr);position:fixed;
  top:0;left:0;bottom:0;display:flex;flex-direction:column;
  overflow-y:auto;z-index:10;
}}
.sb-top{{padding:24px 18px 16px;border-bottom:1px solid var(--bdr)}}
.sb-brand{{
  font-size:18px;font-weight:800;letter-spacing:-.5px;
  background:linear-gradient(135deg,#ff3333,#ff6644);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}}
.sb-sub{{font-size:11px;color:var(--tx3);margin-top:2px;letter-spacing:.3px}}
.sb-sec{{padding:14px 0}}
.sb-sec-lbl{{
  font-size:9px;font-weight:700;color:var(--tx3);
  text-transform:uppercase;letter-spacing:1.2px;padding:0 18px 10px;
}}
.sb-link{{
  display:flex;align-items:center;gap:8px;padding:8px 18px;
  color:var(--tx2);text-decoration:none;font-size:13px;font-weight:500;
  border-left:2px solid transparent;transition:all .15s;cursor:pointer;
}}
.sb-link:hover{{background:#ffffff06;color:var(--tx)}}
.sb-link.act{{background:#ff333308;color:#ff6655;border-left-color:var(--red)}}
.sb-dot{{width:7px;height:7px;border-radius:50%;flex-shrink:0}}
.sb-label{{flex:1}}
.sb-badge,.sb-crit,.sb-high{{
  font-size:10px;font-weight:700;padding:1px 7px;border-radius:8px;
}}
.sb-badge{{background:#ffffff0a;color:var(--tx3)}}
.sb-crit{{background:#ff333320;color:#ff4444}}
.sb-high{{background:#ff663320;color:#ff7755}}
.sb-ov{{font-weight:700;color:var(--tx)!important}}
.sb-foot{{
  margin-top:auto;padding:16px 18px;border-top:1px solid var(--bdr);
  font-size:11px;color:var(--tx3);line-height:1.7;
}}

/* ── Main ── */
.main{{margin-left:230px;flex:1;padding:32px 36px;max-width:1100px}}

/* ── Header ── */
.rpt-hdr{{
  background:var(--s1);border:1px solid var(--bdr);border-radius:var(--r);
  padding:28px 32px;margin-bottom:20px;position:relative;overflow:hidden;
}}
.rpt-hdr::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:linear-gradient(90deg,var(--red),#ff6644,var(--red));
}}
.rpt-title{{font-size:22px;font-weight:800;letter-spacing:-.3px}}
.rpt-meta{{
  display:flex;gap:32px;margin-top:14px;flex-wrap:wrap;
}}
.rm-item{{font-size:12px;color:var(--tx2)}}
.rm-item b{{color:var(--tx);font-weight:600}}

/* Alert */
.alert{{
  background:linear-gradient(135deg,#1a0808,#140606);
  border:1px solid #ff333330;border-radius:var(--r);
  padding:14px 20px;margin-bottom:20px;color:#ff5555;
  font-size:13px;font-weight:600;letter-spacing:.2px;
}}
.alert.hidden{{display:none}}

/* Pills */
.pill-row{{margin-bottom:12px;font-size:13px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.pill-label{{font-weight:600;color:var(--tx2);font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
.pill{{
  display:inline-block;background:var(--s2);border:1px solid var(--bdr2);
  border-radius:20px;padding:3px 12px;font-size:11px;font-weight:600;
}}

/* Search */
.srch{{margin-bottom:22px}}
.srch input{{
  width:100%;background:var(--s1);border:1px solid var(--bdr);
  border-radius:var(--r);padding:11px 16px;color:var(--tx);
  font-size:13px;font-family:var(--sans);outline:none;
  transition:border-color .2s;
}}
.srch input:focus{{border-color:var(--red)}}
.srch input::placeholder{{color:var(--tx3)}}

/* Cards grid */
.cg{{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
  gap:14px;margin-bottom:28px;
}}
.s-card{{
  background:var(--s1);border:1px solid var(--bdr);border-radius:var(--r);
  padding:20px;cursor:pointer;transition:all .2s;position:relative;
  overflow:hidden;
}}
.s-card::after{{
  content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
  background:transparent;transition:background .2s;
}}
.s-card:hover{{
  border-color:var(--bdr2);transform:translateY(-3px);
  box-shadow:0 8px 24px #00000040;
}}
.s-card:hover::after{{background:var(--red)}}
.sc-top{{margin-bottom:6px}}
.sc-sev{{font-size:9px;font-weight:800;letter-spacing:.8px;text-transform:uppercase}}
.sc-num{{font-size:36px;font-weight:800;line-height:1.1;letter-spacing:-1px}}
.sc-name{{font-size:12px;font-weight:600;margin-top:6px;color:var(--tx)}}
.sc-desc{{font-size:11px;color:var(--tx3);margin-top:4px;line-height:1.4}}

/* Sections */
.cat-sec{{animation:fadeUp .2s ease}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:none}}}}
.sec-hdr{{
  display:flex;gap:16px;align-items:flex-start;margin-bottom:18px;
  padding-bottom:16px;border-bottom:1px solid var(--bdr);
}}
.sec-accent{{width:4px;border-radius:4px;min-height:48px;flex-shrink:0}}
.sec-hdr h2{{font-size:18px;font-weight:700}}
.sec-desc{{color:var(--tx2);font-size:13px;margin-top:3px}}
.sec-stat{{font-size:11px;color:var(--red);font-weight:600;margin-top:5px;display:inline-block}}

/* Table */
.tbl-wrap{{
  border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;
}}
.ftbl{{width:100%;border-collapse:collapse;font-size:13px}}
.ftbl th{{
  background:var(--s2);color:var(--tx3);font-weight:600;
  text-align:left;padding:10px 14px;font-size:10px;
  text-transform:uppercase;letter-spacing:.6px;
  border-bottom:1px solid var(--bdr);position:sticky;top:0;
}}
.ftbl td{{padding:9px 14px;border-bottom:1px solid #ffffff08;vertical-align:middle}}
.ftbl tr:last-child td{{border-bottom:none}}
.f-row:hover{{background:#ffffff04}}
code{{font-family:var(--mono);font-size:12px;word-break:break-all;color:var(--tx)}}
.c-ln{{width:55px;color:var(--tx3);font-family:var(--mono);font-size:12px}}
.c-sv{{width:90px}}
.c-ac{{width:56px;text-align:center}}
.fg-hdr{{
  background:var(--s2)!important;font-size:12px;font-weight:600;
  color:var(--tx2);padding:8px 14px!important;
}}
.fg-icon{{
  display:inline-block;background:var(--red);color:#fff;
  font-size:9px;font-weight:800;border-radius:3px;padding:1px 5px;
  margin-right:6px;font-family:var(--mono);
}}
.fg-cnt{{
  float:right;font-weight:500;color:var(--tx3);font-size:11px;margin-right:28px;
}}
.fg-tog{{
  float:right;background:none;border:none;color:var(--tx3);
  cursor:pointer;font-size:9px;padding:0 4px;transition:transform .2s;
}}
.fg-tog.col{{transform:rotate(-90deg)}}
.sv-b{{
  font-size:9px;font-weight:700;padding:3px 8px;
  border-radius:6px;letter-spacing:.4px;display:inline-block;
}}
.cp-btn{{
  background:transparent;border:1px solid var(--bdr2);
  border-radius:6px;cursor:pointer;padding:4px 10px;
  font-size:11px;color:var(--tx3);font-weight:600;
  font-family:var(--sans);transition:all .15s;
}}
.cp-btn:hover{{color:var(--red);border-color:var(--red)}}

/* Confidence */
.cf-high{{color:#ff4444;font-size:10px;font-weight:600}}
.cf-medium{{color:#ffb74d;font-size:10px;font-weight:600}}
.cf-low{{color:#666;font-size:10px;font-weight:600}}

/* Toast */
.toast{{
  position:fixed;bottom:24px;right:24px;background:var(--red);
  color:#fff;padding:10px 20px;border-radius:var(--r);
  font-size:13px;font-weight:600;opacity:0;
  transition:opacity .3s;z-index:100;
  box-shadow:0 4px 20px #ff333340;
}}
.toast.show{{opacity:1}}

/* Overview */
.ov-title{{
  font-size:10px;font-weight:700;color:var(--tx3);
  text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;
}}
</style>
</head>
<body>

<nav class="sb">
  <div class="sb-top">
    <div class="sb-brand">JSVisor</div>
    <div class="sb-sub">Security Report v4.0</div>
  </div>
  <div class="sb-sec">
    <div class="sb-sec-lbl">Navigation</div>
    <a href="#" class="sb-link sb-ov act" data-cat="overview">
      <span class="sb-dot" style="background:var(--red)"></span>
      <span class="sb-label">Overview</span>
      <span class="sb-badge">{total}</span>
    </a>
  </div>
  <div class="sb-sec">
    <div class="sb-sec-lbl">Categories</div>
    {sidebar_items}
  </div>
  <div class="sb-foot">
    Scanned {file_count} file(s)<br>{_esc(scan_time)}
  </div>
</nav>

<main class="main">
  <div class="rpt-hdr">
    <div class="rpt-title">Analysis Report</div>
    <div class="rpt-meta">
      <div class="rm-item"><b>Target</b>&ensp;{_esc(target)}</div>
      <div class="rm-item"><b>Files</b>&ensp;{file_count}</div>
      <div class="rm-item"><b>Findings</b>&ensp;{total}</div>
      <div class="rm-item"><b>Scanned</b>&ensp;{_esc(scan_time)}</div>
    </div>
  </div>

  <div class="alert{alert_cls}">
    {secret_count} potential secret(s) detected -- review immediately.
  </div>

  {fw_html}{cdn_html}

  <div class="srch">
    <input type="text" id="si" placeholder="Search findings by value, source, or line..."
           oninput="sf(this.value)">
  </div>

  <div id="overview" class="cat-sec">
    <div class="ov-title">Summary</div>
    <div class="cg">{cards}</div>
  </div>

  {sections}
</main>

<div id="toast" class="toast">Copied</div>

<script>
(function(){{
  var links=document.querySelectorAll('.sb-link');
  function show(c){{
    document.querySelectorAll('.cat-sec').forEach(function(s){{s.style.display='none'}});
    var id=c==='overview'?'overview':'cat-'+c;
    var el=document.getElementById(id);
    if(el)el.style.display='block';
    links.forEach(function(l){{l.classList.remove('act')}});
    var a=document.querySelector('.sb-link[data-cat="'+c+'"]');
    if(a)a.classList.add('act');
  }}
  links.forEach(function(l){{
    l.addEventListener('click',function(e){{
      e.preventDefault();show(this.getAttribute('data-cat'));
    }});
  }});
  document.querySelectorAll('.s-card').forEach(function(c){{
    c.addEventListener('click',function(){{show(this.getAttribute('data-cat'))}});
  }});
  window.cp=function(t){{
    if(navigator.clipboard)navigator.clipboard.writeText(t).then(tt);
    else{{var a=document.createElement('textarea');a.value=t;
    a.style.position='fixed';a.style.left='-9999px';
    document.body.appendChild(a);a.select();
    document.execCommand('copy');document.body.removeChild(a);tt();}}
  }};
  function tt(){{var t=document.getElementById('toast');
    t.classList.add('show');setTimeout(function(){{t.classList.remove('show')}},1400);}}
  window.tg=function(b){{
    var r=b.closest('tr'),c=b.classList.toggle('col'),n=r.nextElementSibling;
    while(n&&!n.classList.contains('fg-row')){{
      n.style.display=c?'none':'';n=n.nextElementSibling;
    }}
  }};
  window.sf=function(q){{
    if(!q){{document.querySelectorAll('.f-row,.fg-row').forEach(function(r){{r.style.display=''}});return;}}
    var ql=q.toLowerCase();
    document.querySelectorAll('.f-row').forEach(function(r){{
      var v=(r.getAttribute('data-value')||'').toLowerCase();
      var s=(r.getAttribute('data-source')||'').toLowerCase();
      var l=(r.getAttribute('data-line')||'').toLowerCase();
      r.style.display=(v.indexOf(ql)!==-1||s.indexOf(ql)!==-1||l.indexOf(ql)!==-1)?'':'none';
    }});
    document.querySelectorAll('.fg-row').forEach(function(f){{
      var n=f.nextElementSibling,any=false;
      while(n&&!n.classList.contains('fg-row')){{
        if(n.style.display!=='none')any=true;n=n.nextElementSibling;
      }}
      f.style.display=any?'':'none';
    }});
  }};
  show('overview');
}})();
</script>
</body>
</html>"""
