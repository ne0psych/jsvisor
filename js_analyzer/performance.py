#!/usr/bin/env python3
"""
Performance: threaded scanning, incremental cache, .gitignore support.
"""

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Callable

# Try pathspec for .gitignore support
try:
    import pathspec
    HAS_PATHSPEC = True
except ImportError:
    HAS_PATHSPEC = False


# ── Incremental Scanning Cache ───────────────────────────────────────

CACHE_FILE = '.jsvisor_cache.json'


def load_cache(root_dir: str) -> dict:
    """Load the scan cache from disk."""
    cache_path = os.path.join(root_dir, CACHE_FILE)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_cache(root_dir: str, cache: dict):
    """Save the scan cache to disk."""
    cache_path = os.path.join(root_dir, CACHE_FILE)
    try:
        with open(cache_path, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def file_checksum(filepath: str) -> str:
    """Compute SHA-256 checksum of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
    except Exception:
        return ''
    return h.hexdigest()


def filter_changed_files(files: list, root_dir: str, cache: dict) -> tuple:
    """
    Filter files that have changed since last scan.
    Returns (files_to_scan, updated_cache).
    """
    to_scan = []
    new_cache = dict(cache)
    for fp in files:
        fp_str = str(fp)
        checksum = file_checksum(fp_str)
        if cache.get(fp_str) != checksum:
            to_scan.append(fp)
            new_cache[fp_str] = checksum
        # else: skip, unchanged
    return to_scan, new_cache


# ── .gitignore Support ───────────────────────────────────────────────

def load_gitignore_spec(root_dir: str) -> Optional[object]:
    """Load .gitignore patterns from the root directory."""
    if not HAS_PATHSPEC:
        return None
    gitignore_path = os.path.join(root_dir, '.gitignore')
    if not os.path.exists(gitignore_path):
        return None
    try:
        with open(gitignore_path, 'r') as f:
            return pathspec.PathSpec.from_lines('gitwildmatch', f)
    except Exception:
        return None


def filter_gitignore(files: list, root_dir: str, spec) -> list:
    """Filter out files matching .gitignore patterns."""
    if spec is None:
        return files
    result = []
    for fp in files:
        try:
            rel = os.path.relpath(str(fp), root_dir)
            if not spec.match_file(rel):
                result.append(fp)
        except Exception:
            result.append(fp)
    return result


# ── Multi-threaded Scanning ──────────────────────────────────────────

def scan_files_threaded(
    files: list,
    scan_func: Callable,
    thread_count: int = 4,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Scan multiple files using ThreadPoolExecutor.
    scan_func(filepath) -> dict of findings
    progress_callback(completed, total) -> None
    """
    from collections import defaultdict
    combined = defaultdict(list)
    total = len(files)
    completed = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(scan_func, str(fp)): fp for fp in files}
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
                if result:
                    for cat, items in result.items():
                        combined[cat].extend(items)
            except Exception:
                pass
            if progress_callback:
                progress_callback(completed, total)

    return dict(combined)


# ── Large File Streaming ─────────────────────────────────────────────

def read_file_streaming(filepath: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Read a large file in chunks. For files > 10MB, stream and process.
    For smaller files, read normally.
    """
    try:
        file_size = os.path.getsize(filepath)
        if file_size <= 10 * 1024 * 1024:  # 10MB threshold
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        # Stream large files
        content = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                content.append(chunk)
        return ''.join(content)
    except Exception:
        return ''


def collect_js_files_enhanced(
    root: str,
    respect_gitignore: bool = False,
    incremental: bool = False,
) -> tuple:
    """
    Collect JS files with optional .gitignore and incremental support.
    Returns (files_list, cache_dict).
    """
    skip = {'node_modules', '.git', 'dist', '__pycache__', '.cache',
            'build', 'coverage', '.next', '.nuxt'}
    result = []
    for fp in Path(root).rglob("*.js"):
        if not any(part in skip for part in fp.parts):
            result.append(fp)
    result = sorted(result)

    # Apply .gitignore filtering
    if respect_gitignore:
        spec = load_gitignore_spec(root)
        if spec:
            result = filter_gitignore(result, root, spec)

    # Apply incremental filtering
    cache = {}
    if incremental:
        cache = load_cache(root)
        result, cache = filter_changed_files(result, root, cache)

    return result, cache
