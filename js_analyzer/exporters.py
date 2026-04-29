#!/usr/bin/env python3
"""
Output exporters: SARIF, Postman, Markdown.
"""

import json
import datetime
import re
from typing import Optional
from collections import defaultdict


# ── Risk Level Mapping ───────────────────────────────────────────────

RISK_LEVELS = {
    'secrets':    'Critical',
    'network':    'High',
    'cloud':      'Medium',
    'endpoints':  'Medium',
    'urls':       'Medium',
    'emails':     'Low',
    'files':      'Low',
    'sourcemaps': 'Medium',
    'debug':      'Low',
    'graphql':    'Medium',
}


# ── Deduplication ────────────────────────────────────────────────────

def normalize_endpoint(ep: str) -> str:
    """Normalize endpoint for deduplication: remove trailing slash, sort query params."""
    ep = ep.rstrip('/')
    if '?' in ep:
        base, query = ep.split('?', 1)
        params = sorted(query.split('&'))
        ep = base + '?' + '&'.join(params)
    return ep


def deduplicate_findings(findings: dict) -> dict:
    """
    Enhanced deduplication: merge findings that differ only by
    trailing slash or query parameter order.
    """
    result = {}
    for cat, items in findings.items():
        seen = {}
        deduped = []
        for item in items:
            val = item.get('value', '')
            if cat == 'endpoints':
                norm = normalize_endpoint(val)
            else:
                norm = val
            if norm not in seen:
                seen[norm] = True
                deduped.append(item)
        result[cat] = deduped
    return result


# ── SARIF Exporter ───────────────────────────────────────────────────

SARIF_SEVERITY = {
    'Critical': 'error',
    'High': 'error',
    'Medium': 'warning',
    'Low': 'note',
}


def generate_sarif(findings: dict, target: str) -> dict:
    """
    Generate SARIF 2.1.0 format output for GitHub Code Scanning.
    """
    rules = []
    results = []
    rule_index = {}

    for cat, items in findings.items():
        risk = RISK_LEVELS.get(cat, 'Low')
        rule_id = f"jsvisor/{cat}"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": cat.replace('_', ' ').title(),
                "shortDescription": {"text": f"JSVisor: {cat}"},
                "defaultConfiguration": {
                    "level": SARIF_SEVERITY.get(risk, 'note'),
                },
                "properties": {
                    "tags": ["security", cat],
                    "precision": "medium",
                },
            })

        for item in items:
            source = item.get('source', target)
            line = item.get('line', 1)
            result = {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "message": {"text": item.get('value', '')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": source},
                        "region": {"startLine": line},
                    }
                }],
                "level": SARIF_SEVERITY.get(risk, 'note'),
            }
            results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "JSVisor",
                    "version": "4.0.0",
                    "informationUri": "https://github.com/user/jsvisor",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


# ── Postman Collection Exporter ──────────────────────────────────────

def generate_postman_collection(findings: dict, base_url: str = '') -> dict:
    """
    Generate a Postman v2.1 collection of all unique endpoints.
    """
    endpoints = findings.get('endpoints', [])
    urls = findings.get('urls', [])

    items = []
    seen = set()

    for ep in endpoints:
        val = ep.get('value', '')
        norm = normalize_endpoint(val)
        if norm in seen:
            continue
        seen.add(norm)

        url = val
        if val.startswith('/') and base_url:
            url = base_url.rstrip('/') + val

        items.append({
            "name": val,
            "request": {
                "method": "GET",
                "header": [],
                "url": {"raw": url},
                "description": f"Discovered in {ep.get('source', 'unknown')} at line {ep.get('line', '?')}",
            },
        })

    # Also add full URLs
    for u in urls:
        val = u.get('value', '')
        if val not in seen and val.startswith('http'):
            seen.add(val)
            items.append({
                "name": val[:60],
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {"raw": val},
                },
            })

    return {
        "info": {
            "name": "JSVisor - Discovered Endpoints",
            "_postman_id": "",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": f"Auto-generated by JSVisor v4.0 on {datetime.datetime.now().isoformat()}",
        },
        "item": items,
    }


# ── Markdown Summary ─────────────────────────────────────────────────

def generate_markdown_summary(findings: dict, target: str, meta: dict = None) -> str:
    """
    Generate a risk-prioritized Markdown summary.
    Critical > High > Medium > Low
    """
    now = datetime.datetime.now().isoformat(timespec='seconds')
    total = sum(len(v) for v in findings.values())

    lines = [
        f"# JSVisor -- Security Summary",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {now}  ",
        f"**Total findings:** {total}  ",
        f"",
    ]

    # Group by risk level
    by_risk = defaultdict(list)
    for cat, items in findings.items():
        risk = RISK_LEVELS.get(cat, 'Low')
        for item in items:
            by_risk[risk].append((cat, item))

    risk_order = ['Critical', 'High', 'Medium', 'Low']
    risk_label = {'Critical': '[CRITICAL]', 'High': '[HIGH]', 'Medium': '[MEDIUM]', 'Low': '[LOW]'}

    for risk in risk_order:
        items = by_risk.get(risk, [])
        if not items:
            continue
        lines.append(f"## {risk_label[risk]} {risk} ({len(items)})")
        lines.append("")

        # Group by category
        by_cat = defaultdict(list)
        for cat, item in items:
            by_cat[cat].append(item)

        for cat, cat_items in by_cat.items():
            lines.append(f"### {cat.title()} ({len(cat_items)})")
            lines.append("")
            for item in cat_items[:20]:  # Limit to 20 per category
                val = item.get('value', '')
                src = item.get('source', '')
                ln = item.get('line', '?')
                lines.append(f"- `{val}` — {src}:{ln}")
            if len(cat_items) > 20:
                lines.append(f"- ... and {len(cat_items) - 20} more")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by JSVisor v4.0*")
    return '\n'.join(lines)
