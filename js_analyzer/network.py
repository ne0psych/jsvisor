#!/usr/bin/env python3
"""
Enhanced Network & Infrastructure Discovery

- Resolve relative endpoints to absolute URLs using base URL
- Detect API versioning schemes and suggest bruteforce list
- GraphQL introspection (optional, user-enabled)
- Swagger/OpenAPI/api-docs detection
"""

import re
import json
from urllib.parse import urljoin
from typing import Optional


# ── Swagger / OpenAPI Detection ──────────────────────────────────────

SWAGGER_PATTERNS = [
    re.compile(r'["\']([^"\']*swagger\.json)["\']', re.I),
    re.compile(r'["\']([^"\']*openapi\.json)["\']', re.I),
    re.compile(r'["\']([^"\']*api-docs[^"\']*)["\']', re.I),
    re.compile(r'["\']([^"\']*swagger-ui[^"\']*)["\']', re.I),
    re.compile(r'["\']([^"\']*redoc[^"\']*)["\']', re.I),
]


def detect_swagger_refs(text: str, line_of_func) -> list:
    """Find references to Swagger/OpenAPI documentation endpoints."""
    results = []
    seen = set()
    for pat in SWAGGER_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1)
            if val and val not in seen:
                seen.add(val)
                results.append({
                    'value': f"API Docs: {val}",
                    'line': line_of_func(m.start()),
                    'type': 'Swagger/OpenAPI',
                })
    return results


# ── Relative URL Resolution ─────────────────────────────────────────

def resolve_endpoints(endpoints: list, base_url: str) -> list:
    """
    Resolve relative endpoints to absolute URLs using a base URL.
    Each endpoint is a dict with 'value' key.
    Returns new list with resolved URLs added.
    """
    if not base_url:
        return endpoints

    # Ensure base_url has protocol
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url

    resolved = []
    for ep in endpoints:
        val = ep.get('value', '')
        if val.startswith('/'):
            absolute = urljoin(base_url, val)
            new_ep = dict(ep)
            new_ep['resolved_url'] = absolute
            resolved.append(new_ep)
        else:
            resolved.append(ep)
    return resolved


# ── API Versioning & Bruteforce List ─────────────────────────────────

VERSION_PATTERN = re.compile(r'/v(\d+)(?:\.\d+)?/')


def detect_api_versions(endpoints: list) -> dict:
    """
    Detect API versioning schemes from endpoints.
    Returns dict with 'versions_found', 'suggested_bruteforce'.
    """
    versions = set()
    base_paths = set()

    for ep in endpoints:
        val = ep.get('value', '')
        m = VERSION_PATTERN.search(val)
        if m:
            versions.add(int(m.group(1)))
            # Extract the base path template
            base = VERSION_PATTERN.sub('/v{VERSION}/', val)
            base_paths.add(base)

    if not versions:
        return {'versions_found': [], 'suggested_bruteforce': []}

    max_ver = max(versions)
    # Suggest checking versions 1 through max+2
    suggested = []
    for base in base_paths:
        for v in range(1, max_ver + 3):
            suggested.append(base.replace('{VERSION}', str(v)))

    return {
        'versions_found': sorted(versions),
        'suggested_bruteforce': suggested[:50],  # Cap at 50
    }


# ── GraphQL Introspection ───────────────────────────────────────────

INTROSPECTION_QUERY = '''
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
'''.strip()


def perform_graphql_introspection(endpoint_url: str, no_network: bool = False) -> Optional[dict]:
    """
    Perform a GraphQL introspection query against the given endpoint.
    Only runs if user explicitly enabled --graphql-introspect.
    Returns the schema dict or None on failure.
    """
    if no_network:
        return None

    from urllib.request import Request, urlopen
    import json

    payload = json.dumps({'query': INTROSPECTION_QUERY}).encode('utf-8')
    try:
        req = Request(
            endpoint_url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'JSVisor/4.0',
            },
        )
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('data', {}).get('__schema')
    except Exception:
        return None
