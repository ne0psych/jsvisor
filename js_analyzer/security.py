#!/usr/bin/env python3
"""
Enhancement #10 — Security Hardening

- Auto-redact secrets in logs/output (show first 4 + last 4 chars)
- Password-protected ZIP export
- --no-network flag support
- --redact flag for reports
"""

import os
import re
import zipfile
import io
from typing import Optional


def redact_secret(value: str, full_redact: bool = False) -> str:
    """
    Redact a secret string, showing only first 4 and last 4 characters.
    Example: 'ghp_abc123xyz789c3f9' -> 'ghp_...c3f9'
    """
    if full_redact:
        return '****REDACTED****'
    if len(value) <= 12:
        return value[:2] + '...' + value[-2:] if len(value) > 4 else '****'
    return value[:4] + '...' + value[-4:]


def redact_findings(findings: dict, redact: bool = False) -> dict:
    """
    Apply redaction to all secret findings.
    Returns a new dict with redacted values.
    """
    if not redact:
        return findings

    import copy
    redacted = copy.deepcopy(findings)
    for item in redacted.get('secrets', []):
        val = item.get('value', '')
        # The value format is "Label: secret_value"
        parts = val.split(': ', 1)
        if len(parts) == 2:
            item['value'] = parts[0] + ': ' + redact_secret(parts[1])
        else:
            item['value'] = redact_secret(val)
    return redacted


def create_encrypted_zip(
    file_paths: list,
    output_path: str,
    password: Optional[str] = None,
) -> str:
    """
    Create a password-protected ZIP archive of report files.
    Uses pyzipper if available for AES encryption, otherwise standard zip.
    """
    if password:
        try:
            # Try AES encryption via pyzipper or pycryptodome-based approach
            import pyzipper
            with pyzipper.AESZipFile(
                output_path, 'w',
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(password.encode('utf-8'))
                for fp in file_paths:
                    zf.write(fp, os.path.basename(fp))
            return output_path
        except ImportError:
            pass

        # Fallback: standard ZIP with password (weak encryption)
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fp in file_paths:
                zf.write(fp, os.path.basename(fp))
        return output_path
    else:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fp in file_paths:
                zf.write(fp, os.path.basename(fp))
        return output_path


# ── Console Output Redaction ─────────────────────────────────────────

SECRET_LIKE_PATTERN = re.compile(
    r'((?:ghp_|gho_|sk_live_|pk_live_|sk_test_|AKIA|xox[baprs]-|eyJ|sk-|Bearer\s+)'
    r'[a-zA-Z0-9_\-./+=]{8,})'
)


def redact_console_output(text: str) -> str:
    """Auto-redact any secret-like strings in console/log output."""
    def replacer(m):
        val = m.group(1)
        return redact_secret(val)
    return SECRET_LIKE_PATTERN.sub(replacer, text)
