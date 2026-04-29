#!/usr/bin/env python3
"""
Enhancement #5 — Repository & Dependency Analysis

- Parse package.json for dependencies and known vulnerabilities
- Detect process.env.* without default values (env injection risk)
- Extract .git metadata (commit hash, branch name)
- Detect exposed .git/config
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional


def parse_package_json(root_dir: str) -> Optional[dict]:
    """
    Look for package.json in the scan root and parse it.
    Returns dict with 'name', 'version', 'dependencies', 'devDependencies'.
    """
    pkg_path = Path(root_dir) / 'package.json'
    if not pkg_path.exists():
        return None
    try:
        with open(pkg_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return {
            'name': data.get('name', 'unknown'),
            'version': data.get('version', '0.0.0'),
            'dependencies': data.get('dependencies', {}),
            'devDependencies': data.get('devDependencies', {}),
            'scripts': data.get('scripts', {}),
        }
    except Exception:
        return None


# ── Known Vulnerable Packages (local DB) ─────────────────────────────

KNOWN_VULNERABLE = {
    'lodash': {'below': '4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'High'},
    'minimist': {'below': '1.2.6', 'cve': 'CVE-2021-44906', 'severity': 'Critical'},
    'node-fetch': {'below': '2.6.7', 'cve': 'CVE-2022-0235', 'severity': 'High'},
    'express': {'below': '4.17.3', 'cve': 'CVE-2022-24999', 'severity': 'High'},
    'jsonwebtoken': {'below': '9.0.0', 'cve': 'CVE-2022-23529', 'severity': 'Critical'},
    'axios': {'below': '0.21.2', 'cve': 'CVE-2021-3749', 'severity': 'High'},
    'tar': {'below': '6.1.9', 'cve': 'CVE-2021-37712', 'severity': 'High'},
    'glob-parent': {'below': '5.1.2', 'cve': 'CVE-2020-28469', 'severity': 'High'},
    'path-parse': {'below': '1.0.7', 'cve': 'CVE-2021-23343', 'severity': 'Medium'},
    'underscore': {'below': '1.13.6', 'cve': 'CVE-2021-23358', 'severity': 'High'},
}


def _version_lt(a: str, b: str) -> bool:
    """Simple semver less-than comparison."""
    def parse(v):
        v = re.sub(r'[^\d.]', '', v.lstrip('^~>=<'))
        parts = v.split('.')
        return [int(p) for p in parts if p.isdigit()][:3]
    va, vb = parse(a), parse(b)
    while len(va) < 3: va.append(0)
    while len(vb) < 3: vb.append(0)
    return va < vb


def check_vulnerable_deps(pkg_info: dict) -> list:
    """Check dependencies against known vulnerability DB."""
    results = []
    all_deps = {}
    all_deps.update(pkg_info.get('dependencies', {}))
    all_deps.update(pkg_info.get('devDependencies', {}))

    for name, version in all_deps.items():
        if name in KNOWN_VULNERABLE:
            vuln = KNOWN_VULNERABLE[name]
            clean_ver = re.sub(r'[^0-9.]', '', version)
            if clean_ver and _version_lt(clean_ver, vuln['below']):
                results.append({
                    'package': name,
                    'installed': version,
                    'fixed_in': vuln['below'],
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                })
    return results


# ── process.env without default ──────────────────────────────────────

ENV_NO_DEFAULT = re.compile(
    r'process\.env\.([A-Z_]{3,})\b(?!\s*(?:\|\||&&|\?\?))'
)


def find_env_injection_risks(text: str, line_of_func) -> list:
    """Find process.env.* references without a default value."""
    results = []
    seen = set()
    for m in ENV_NO_DEFAULT.finditer(text):
        var_name = m.group(1)
        if var_name not in seen:
            seen.add(var_name)
            results.append({
                'value': f"Env injection risk: process.env.{var_name} (no default)",
                'line': line_of_func(m.start()),
                'type': 'Env Injection Risk',
            })
    return results


# ── .git Metadata Extraction ────────────────────────────────────────

def extract_git_info(root_dir: str) -> Optional[dict]:
    """
    If .git directory exists, extract commit hash and branch name
    without copying any files. Also detect exposed .git/config.
    """
    git_dir = Path(root_dir) / '.git'
    if not git_dir.is_dir():
        return None

    info = {'git_detected': True, 'exposed_config': False}

    # Read HEAD for branch name
    head_file = git_dir / 'HEAD'
    if head_file.exists():
        try:
            content = head_file.read_text().strip()
            if content.startswith('ref: refs/heads/'):
                info['branch'] = content.replace('ref: refs/heads/', '')
            else:
                info['branch'] = 'detached'
                info['commit'] = content[:12]
        except Exception:
            pass

    # Try to get commit hash from packed-refs or ref file
    if 'commit' not in info and 'branch' in info:
        ref_file = git_dir / 'refs' / 'heads' / info['branch']
        if ref_file.exists():
            try:
                info['commit'] = ref_file.read_text().strip()[:12]
            except Exception:
                pass

    # Check if .git/config is accessible (exposed)
    config_file = git_dir / 'config'
    if config_file.exists():
        info['exposed_config'] = True
        try:
            content = config_file.read_text()
            # Extract remote URLs
            remotes = re.findall(r'url\s*=\s*(.+)', content)
            if remotes:
                info['remotes'] = [r.strip() for r in remotes]
        except Exception:
            pass

    return info
