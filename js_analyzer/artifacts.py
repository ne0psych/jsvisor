#!/usr/bin/env python3
"""
Artifact detection: WebAssembly, browser storage, CORS, CDN.
"""

import re
from collections import Counter


# ── WebAssembly Detection ────────────────────────────────────────────

WASM_PATTERNS = [
    (re.compile(r'WebAssembly\.instantiate(?:Streaming)?\s*\('), 'WebAssembly.instantiate'),
    (re.compile(r'WebAssembly\.compile(?:Streaming)?\s*\('), 'WebAssembly.compile'),
    (re.compile(r'WebAssembly\.Module\s*\('), 'WebAssembly.Module'),
    (re.compile(r'["\']([^"\']+\.wasm)["\']'), 'WASM import'),
    (re.compile(r'new\s+WebAssembly\.Instance\s*\('), 'WebAssembly.Instance'),
]

WASM_EXPORT_PATTERN = re.compile(
    r'(?:instance|module)\.exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)'
)


def detect_wasm(text: str, line_of_func) -> list:
    """Detect WebAssembly usage and extract exported function names."""
    results = []
    seen = set()
    for pat, label in WASM_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0).strip()
            key = f"{label}:{val}"
            if key not in seen:
                seen.add(key)
                results.append({
                    'value': f"{label}: {val}",
                    'line': line_of_func(m.start()),
                    'type': label,
                })
    # Extract exported function names
    for m in WASM_EXPORT_PATTERN.finditer(text):
        fn_name = m.group(1)
        key = f"wasm_export:{fn_name}"
        if key not in seen:
            seen.add(key)
            results.append({
                'value': f"WASM Export: {fn_name}",
                'line': line_of_func(m.start()),
                'type': 'WASM Export',
            })
    return results


# ── Browser Storage Keys ────────────────────────────────────────────

STORAGE_PATTERNS = [
    (re.compile(r'localStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']'), 'localStorage'),
    (re.compile(r'localStorage\[[\s]*["\']([^"\']+)["\']\s*\]'), 'localStorage'),
    (re.compile(r'sessionStorage\.(?:getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']'), 'sessionStorage'),
    (re.compile(r'sessionStorage\[[\s]*["\']([^"\']+)["\']\s*\]'), 'sessionStorage'),
]

INDEXEDDB_PATTERNS = [
    re.compile(r'indexedDB\.open\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'createObjectStore\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'transaction\s*\(\s*\[?\s*["\']([^"\']+)["\']'),
]


def detect_browser_storage(text: str, line_of_func) -> list:
    """List all keys accessed in localStorage, sessionStorage, and IndexedDB."""
    results = []
    seen = set()
    for pat, storage_type in STORAGE_PATTERNS:
        for m in pat.finditer(text):
            key = m.group(1)
            uid = f"{storage_type}:{key}"
            if uid not in seen:
                seen.add(uid)
                results.append({
                    'value': f"Browser storage key ({storage_type}): {key}",
                    'line': line_of_func(m.start()),
                    'type': f'{storage_type} key',
                })
    for pat in INDEXEDDB_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            uid = f"indexedDB:{name}"
            if uid not in seen:
                seen.add(uid)
                results.append({
                    'value': f"IndexedDB store/db: {name}",
                    'line': line_of_func(m.start()),
                    'type': 'IndexedDB',
                })
    return results


# ── CORS Misconfiguration Detection ─────────────────────────────────

CORS_PATTERNS = [
    (re.compile(r'Access-Control-Allow-Origin\s*[":]\s*\*'), 'Wildcard ACAO'),
    (re.compile(r'credentials\s*:\s*["\']include["\']'), 'credentials: include'),
    (re.compile(r'Access-Control-Allow-Credentials\s*[":]\s*true', re.I), 'ACAC: true'),
    (re.compile(r'cors\s*\(\s*\{[^}]*origin\s*:\s*true', re.S), 'CORS origin: true (all)'),
    (re.compile(r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']\*["\']', re.S), 'CORS origin: *'),
]


def detect_cors_misconfig(text: str, line_of_func) -> list:
    """Flag CORS misconfigurations."""
    results = []
    seen = set()
    for pat, label in CORS_PATTERNS:
        for m in pat.finditer(text):
            if label not in seen:
                seen.add(label)
                results.append({
                    'value': f"CORS Misconfiguration: {label}",
                    'line': line_of_func(m.start()),
                    'type': 'CORS Misconfiguration',
                })
    return results


# ── CDN/Cloud Provider Summary ───────────────────────────────────────

CDN_DOMAINS = {
    'cloudfront.net': 'AWS CloudFront',
    'azureedge.net': 'Azure CDN',
    'akamaihd.net': 'Akamai',
    'akamaized.net': 'Akamai',
    'cloudflare.com': 'Cloudflare',
    'cdn.cloudflare.net': 'Cloudflare',
    'fastly.net': 'Fastly',
    'googleapis.com': 'Google Cloud',
    'gstatic.com': 'Google Static',
    'amazonaws.com': 'AWS',
    'azurewebsites.net': 'Azure',
    'blob.core.windows.net': 'Azure Blob',
    'digitaloceanspaces.com': 'DigitalOcean',
    'jsdelivr.net': 'jsDelivr CDN',
    'unpkg.com': 'unpkg CDN',
    'cdnjs.cloudflare.com': 'cdnjs',
    'stackpath.bootstrapcdn.com': 'StackPath/Bootstrap CDN',
}

URL_EXTRACT = re.compile(r'https?://([a-zA-Z0-9.-]+)')


def summarize_cdn_usage(text: str) -> dict:
    """
    If multiple URLs point to CDN/cloud domains, summarize providers.
    Returns dict mapping provider name to list of domains found.
    """
    domain_counts = Counter()
    provider_domains = {}

    for m in URL_EXTRACT.finditer(text):
        domain = m.group(1).lower()
        for cdn_domain, provider in CDN_DOMAINS.items():
            if domain.endswith(cdn_domain):
                domain_counts[provider] += 1
                if provider not in provider_domains:
                    provider_domains[provider] = set()
                provider_domains[provider].add(domain)
                break

    return {
        provider: {
            'count': domain_counts[provider],
            'domains': sorted(domains),
        }
        for provider, domains in provider_domains.items()
    }
