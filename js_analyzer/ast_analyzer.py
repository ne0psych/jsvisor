#!/usr/bin/env python3
"""
Advanced Dynamic Analysis (AST-based)

- AST parsing via esprima for endpoint extraction
- Deobfuscation: \\xHH, \\uXXXX escape unpacking
- atob/btoa resolution for static string arguments
- Trivial arithmetic/concatenation evaluation
"""

import re
from typing import Optional

# Try to import esprima; gracefully degrade if not available
try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False


# ── String Deobfuscation ────────────────────────────────────────────

def unescape_hex_unicode(text: str) -> str:
    """Unpack \\xHH and \\uXXXX escapes to readable characters."""
    def replace_hex(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    def replace_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    text = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, text)
    text = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, text)
    return text


def resolve_atob_btoa(text: str) -> str:
    """
    Replace atob("base64_string") with the decoded value when argument is
    a static string literal. Same for btoa (encode).
    """
    import base64

    def decode_atob(m):
        try:
            raw = m.group(1)
            decoded = base64.b64decode(raw).decode('utf-8', errors='replace')
            return f'"{decoded}"'
        except Exception:
            return m.group(0)

    def encode_btoa(m):
        try:
            raw = m.group(1)
            encoded = base64.b64encode(raw.encode('utf-8')).decode('ascii')
            return f'"{encoded}"'
        except Exception:
            return m.group(0)

    text = re.sub(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)', decode_atob, text)
    text = re.sub(r'btoa\s*\(\s*["\']([^"\']+)["\']\s*\)', encode_btoa, text)
    return text


def evaluate_simple_concat(text: str) -> str:
    """
    Evaluate trivial string concatenation patterns:
    "abc" + "def" -> "abcdef"
    Also handles: 'a' + 'b' + 'c'
    """
    # Iteratively collapse adjacent string concatenations
    pattern = re.compile(r'(["\'])([^"\']*)\1\s*\+\s*(["\'])([^"\']*)\3')
    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(lambda m: f'"{m.group(2)}{m.group(4)}"', text)
    return text


def evaluate_char_code_tricks(text: str) -> str:
    """
    Evaluate String.fromCharCode(72,101,108,108,111) patterns.
    """
    def replace_charcode(m):
        try:
            codes = [int(c.strip()) for c in m.group(1).split(',')]
            return '"' + ''.join(chr(c) for c in codes) + '"'
        except (ValueError, OverflowError):
            return m.group(0)

    text = re.sub(
        r'String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)',
        replace_charcode, text
    )
    return text


def deobfuscate(text: str) -> str:
    """Apply all deobfuscation steps."""
    text = unescape_hex_unicode(text)
    text = resolve_atob_btoa(text)
    text = evaluate_simple_concat(text)
    text = evaluate_char_code_tricks(text)
    return text


# ── AST-based Endpoint Extraction ───────────────────────────────────

def extract_endpoints_ast(source: str) -> list:
    """
    Use esprima to parse JS and extract string literals that look like
    API endpoints from fetch(), axios, XMLHttpRequest, $.ajax, etc.

    Returns list of dicts with 'value', 'line', 'type'.
    """
    if not HAS_ESPRIMA:
        return []

    results = []
    seen = set()

    try:
        tree = esprima.parseScript(source, loc=True, tolerant=True)
    except Exception:
        try:
            tree = esprima.parseModule(source, loc=True, tolerant=True)
        except Exception:
            return []

    endpoint_re = re.compile(r'^(?:https?://|/(?:api|v\d|rest|graphql|auth|admin|internal))')

    def visit(node):
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not hasattr(node, 'type'):
            return

        # Extract string literals from call expressions
        if node.type == 'CallExpression':
            _extract_from_call(node, results, seen, endpoint_re)

        # Recurse into all properties
        for key in dir(node):
            if key.startswith('_'):
                continue
            child = getattr(node, key, None)
            if child is not None and hasattr(child, 'type'):
                visit(child)
            elif isinstance(child, list):
                visit(child)

    def _extract_from_call(node, results, seen, pat):
        callee = node.callee
        callee_name = _get_callee_name(callee)

        # fetch(), axios.get/post/put/delete(), $.ajax(), XMLHttpRequest.open()
        fetch_names = {'fetch', 'axios', 'get', 'post', 'put', 'delete', 'patch',
                       'request', 'ajax', 'open', 'navigate'}

        if callee_name and any(n in callee_name.lower() for n in fetch_names):
            for arg in (node.arguments or []):
                _extract_strings(arg, results, seen, pat)

        # Also check all arguments for URL-like strings
        for arg in (node.arguments or []):
            if hasattr(arg, 'type') and arg.type == 'Literal' and isinstance(getattr(arg, 'value', None), str):
                val = arg.value
                if pat.match(val) and val not in seen:
                    seen.add(val)
                    line = getattr(arg, 'loc', None)
                    ln = line.start.line if line else 0
                    results.append({
                        'value': val,
                        'line': ln,
                        'type': 'AST-extracted endpoint',
                    })

    def _get_callee_name(callee):
        if not callee:
            return None
        if hasattr(callee, 'name'):
            return callee.name
        if hasattr(callee, 'property') and hasattr(callee.property, 'name'):
            obj_name = ''
            if hasattr(callee, 'object') and hasattr(callee.object, 'name'):
                obj_name = callee.object.name + '.'
            return obj_name + callee.property.name
        return None

    def _extract_strings(node, results, seen, pat):
        if not node:
            return
        if hasattr(node, 'type') and node.type == 'Literal':
            val = getattr(node, 'value', None)
            if isinstance(val, str) and pat.match(val) and val not in seen:
                seen.add(val)
                line = getattr(node, 'loc', None)
                ln = line.start.line if line else 0
                results.append({
                    'value': val,
                    'line': ln,
                    'type': 'AST-extracted endpoint',
                })
        elif hasattr(node, 'type') and node.type == 'TemplateLiteral':
            for quasi in (getattr(node, 'quasis', None) or []):
                val = getattr(quasi, 'value', None)
                if val:
                    raw = getattr(val, 'raw', '') or ''
                    if pat.match(raw) and raw not in seen:
                        seen.add(raw)
                        line = getattr(quasi, 'loc', None)
                        ln = line.start.line if line else 0
                        results.append({
                            'value': raw,
                            'line': ln,
                            'type': 'AST-extracted endpoint (template)',
                        })

    visit(tree.body)
    return results


def extract_all_strings_ast(source: str) -> list:
    """
    Extract all string literals from JS source via AST.
    Returns list of (value, line_number) tuples.
    """
    if not HAS_ESPRIMA:
        return []

    results = []
    try:
        tree = esprima.parseScript(source, loc=True, tolerant=True)
    except Exception:
        try:
            tree = esprima.parseModule(source, loc=True, tolerant=True)
        except Exception:
            return []

    def visit(node):
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not hasattr(node, 'type'):
            return
        if node.type == 'Literal' and isinstance(getattr(node, 'value', None), str):
            line = getattr(node, 'loc', None)
            ln = line.start.line if line else 0
            results.append((node.value, ln))
        for key in dir(node):
            if key.startswith('_'):
                continue
            child = getattr(node, key, None)
            if child is not None and hasattr(child, 'type'):
                visit(child)
            elif isinstance(child, list):
                visit(child)

    visit(tree.body)
    return results
