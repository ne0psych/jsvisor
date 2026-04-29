#!/usr/bin/env python3
"""
Better Credential & Secret Detection

- Shannon entropy scoring for strings > 16 chars (flag if > 4.5)
- Context-aware filtering: lower confidence for comments, test/example/dummy
- Known secret format validation (AWS key length/charset, etc.)
- Hardcoded JWT secret and default admin credential detection
"""

import math
import re
from typing import Optional


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_high_entropy(s: str, threshold: float = 4.5) -> bool:
    """Return True if string has entropy above threshold."""
    return len(s) >= 16 and shannon_entropy(s) > threshold


def assess_confidence(value: str, line_text: str, label: str) -> str:
    """
    Assess confidence of a secret finding.

    Returns: 'high', 'medium', or 'low'
    """
    low_indicators = ['example', 'test', 'dummy', 'placeholder', 'sample',
                      'your_', 'xxxx', 'changeme', 'insert', 'todo', 'fixme']
    vl = value.lower()
    ll = line_text.lower()

    # Check if inside a comment block
    stripped = line_text.strip()
    in_comment = stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*')

    # Check for low-confidence indicators
    has_low_indicator = any(ind in vl or ind in ll for ind in low_indicators)

    if in_comment or has_low_indicator:
        return 'low'

    # High confidence for known formats
    if label in ('AWS Access Key', 'GitHub PAT', 'Stripe Live Secret',
                 'Private Key', 'Slack Token', 'JWT Token'):
        return 'high'

    # Medium for generic patterns
    return 'medium'


# ── Known Secret Format Validation ───────────────────────────────────

def validate_aws_access_key(value: str) -> bool:
    """AWS Access Key: starts with AKIA, exactly 20 chars, uppercase + digits."""
    if not value.startswith('AKIA'):
        return False
    return len(value) == 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' for c in value)


def validate_aws_secret_key(value: str) -> bool:
    """AWS Secret Key: exactly 40 chars, base64-ish charset."""
    import string
    valid = set(string.ascii_letters + string.digits + '/+=')
    return len(value) == 40 and all(c in valid for c in value)


def validate_github_pat(value: str) -> bool:
    """GitHub PAT: starts with ghp_, 40 chars total."""
    return value.startswith('ghp_') and len(value) == 40


def validate_stripe_key(value: str) -> bool:
    """Stripe keys: sk_live_ or pk_live_ prefix, 24+ alphanumeric suffix."""
    return bool(re.match(r'^[sp]k_(live|test)_[0-9a-zA-Z]{24,}$', value))


def validate_jwt(value: str) -> bool:
    """Basic JWT structure validation: 3 base64url-encoded parts."""
    parts = value.split('.')
    if len(parts) != 3:
        return False
    import base64
    for part in parts[:2]:
        padded = part + '=' * (4 - len(part) % 4)
        try:
            base64.urlsafe_b64decode(padded)
        except Exception:
            return False
    return True


SECRET_VALIDATORS = {
    'AWS Access Key': validate_aws_access_key,
    'GitHub PAT': validate_github_pat,
    'Stripe Live Secret': validate_stripe_key,
    'Stripe Test Secret': validate_stripe_key,
    'JWT Token': validate_jwt,
}


def validate_secret_format(value: str, label: str) -> Optional[bool]:
    """
    Validate a secret against known format rules.
    Returns True if valid, False if invalid, None if no validator exists.
    """
    validator = SECRET_VALIDATORS.get(label)
    if validator is None:
        return None
    return validator(value)


# ── Additional Secret Patterns ───────────────────────────────────────

JWT_SECRET_PATTERNS = [
    re.compile(r'(?i)(?:hmac|jwt|signing).{0,16}(?:secret|key)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    re.compile(r'(?i)(?:secret|key)\s*[=:]\s*["\']([^"\']{8,})["\'].*(?:hmac|jwt|sign)', re.DOTALL),
]

ADMIN_CREDENTIAL_PATTERNS = [
    re.compile(r'(?i)(?:username|user)\s*[=:]\s*["\']admin["\']'),
    re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']admin["\']'),
    re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'](?:password|123456|root|admin|default)["\']'),
    re.compile(r'(?i)(?:username|user)\s*[=:]\s*["\']root["\']'),
]


def find_jwt_secrets(text: str, line_of_func) -> list:
    """Find hardcoded JWT/HMAC secrets."""
    results = []
    for pat in JWT_SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            results.append({
                'value': f"JWT/HMAC Secret: {val[:10]}...{val[-4:]}" if len(val) > 20 else f"JWT/HMAC Secret: {val}",
                'line': line_of_func(m.start()),
                'type': 'JWT/HMAC Secret',
                'confidence': 'high',
                'raw_len': len(val),
            })
    return results


def find_admin_credentials(text: str, line_of_func) -> list:
    """Find default/admin credentials."""
    results = []
    for pat in ADMIN_CREDENTIAL_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0).strip()
            results.append({
                'value': f"Default Credential: {val}",
                'line': line_of_func(m.start()),
                'type': 'Default Credential',
                'confidence': 'high',
            })
    return results


def find_high_entropy_strings(text: str, line_of_func) -> list:
    """
    Find high-entropy strings that may be secrets.
    Scans all quoted strings > 16 chars with entropy > 4.5.
    """
    results = []
    seen = set()
    pattern = re.compile(r'["\']([A-Za-z0-9+/=_\-]{16,})["\']')
    for m in pattern.finditer(text):
        val = m.group(1)
        if val in seen:
            continue
        seen.add(val)
        ent = shannon_entropy(val)
        if ent > 4.5:
            results.append({
                'value': f"High-entropy candidate (entropy={ent:.2f}): {val[:10]}...{val[-4:]}",
                'line': line_of_func(m.start()),
                'type': 'High-entropy string',
                'confidence': 'medium',
                'entropy': round(ent, 2),
                'raw_len': len(val),
            })
    return results
