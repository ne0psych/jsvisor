#!/usr/bin/env python3
"""
Framework-Specific Knowledge

Detect React/Vue/Angular, Next.js/Nuxt patterns, Webpack DefinePlugin,
jQuery $.ajax(), and Axios calls.
"""

import re


# ── Framework Detection ──────────────────────────────────────────────

FRAMEWORK_INDICATORS = {
    'react': [
        re.compile(r'\bReact\.createElement\b'),
        re.compile(r'\buseState\b'),
        re.compile(r'\buseEffect\b'),
        re.compile(r'\bReactDOM\b'),
        re.compile(r'from\s+["\']react["\']'),
        re.compile(r'import\s+React\b'),
    ],
    'vue': [
        re.compile(r'\bVue\.component\b'),
        re.compile(r'\bcreateApp\b'),
        re.compile(r'\bdefineComponent\b'),
        re.compile(r'from\s+["\']vue["\']'),
        re.compile(r'\bVue\.use\b'),
    ],
    'angular': [
        re.compile(r'@Component\s*\('),
        re.compile(r'@Injectable\s*\('),
        re.compile(r'@NgModule\s*\('),
        re.compile(r'\bngOnInit\b'),
        re.compile(r'\bngOnDestroy\b'),
        re.compile(r'from\s+["\']@angular/'),
    ],
    'nextjs': [
        re.compile(r'\bgetServerSideProps\b'),
        re.compile(r'\bgetStaticProps\b'),
        re.compile(r'\bgetStaticPaths\b'),
        re.compile(r'from\s+["\']next/'),
        re.compile(r'\bnext\.config\b'),
    ],
    'nuxt': [
        re.compile(r'\buseFetch\b'),
        re.compile(r'\buseAsyncData\b'),
        re.compile(r'\bdefineNuxtConfig\b'),
        re.compile(r'from\s+["\']#app["\']'),
        re.compile(r'\bnuxt\.config\b'),
    ],
}


def detect_frameworks(text: str) -> list:
    """Detect which JS frameworks are used in the source."""
    detected = []
    for fw, patterns in FRAMEWORK_INDICATORS.items():
        for pat in patterns:
            if pat.search(text):
                detected.append(fw)
                break
    return detected


# ── Framework-Specific Endpoint Extraction ───────────────────────────

FRAMEWORK_ENDPOINT_PATTERNS = [
    # jQuery $.ajax()
    (re.compile(r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.S), 'jQuery $.ajax'),
    (re.compile(r'\$\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']'), 'jQuery HTTP method'),
    # Axios
    (re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']'), 'Axios call'),
    (re.compile(r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.S), 'Axios config'),
    (re.compile(r'axios\s*\.\s*create\s*\(\s*\{[^}]*baseURL\s*:\s*["\']([^"\']+)["\']', re.S), 'Axios baseURL'),
    # React/Next.js fetch patterns
    (re.compile(r'(?:useSWR|useQuery)\s*\(\s*["\']([^"\']+)["\']'), 'React data hook'),
    (re.compile(r'(?:getServerSideProps|getStaticProps).*?fetch\s*\(\s*["\']([^"\']+)["\']', re.S), 'Next.js SSR fetch'),
    # Angular HttpClient
    (re.compile(r'(?:http|httpClient)\s*\.\s*(?:get|post|put|delete|patch)\s*(?:<[^>]+>)?\s*\(\s*["\']([^"\']+)["\']'), 'Angular HttpClient'),
    # Vue/Nuxt
    (re.compile(r'(?:\$axios|\$fetch|useFetch)\s*\(\s*["\']([^"\']+)["\']'), 'Vue/Nuxt fetch'),
]

# ── Next.js/Nuxt Environment Variables ──────────────────────────────

ENV_VAR_PATTERNS = [
    (re.compile(r'process\.env\.(NEXT_PUBLIC_[A-Z_]+)\b'), 'Next.js public env'),
    (re.compile(r'process\.env\.(NUXT_PUBLIC_[A-Z_]+)\b'), 'Nuxt public env'),
    (re.compile(r'process\.env\.(REACT_APP_[A-Z_]+)\b'), 'React env'),
    (re.compile(r'process\.env\.([A-Z_]{3,})\b'), 'Environment variable'),
    (re.compile(r'import\.meta\.env\.(VITE_[A-Z_]+)\b'), 'Vite env'),
]

# ── Next.js API Routes ──────────────────────────────────────────────

NEXTJS_API_ROUTE = re.compile(r'["\'](?:/api/[a-zA-Z0-9/_\-]+)["\']')

# ── Webpack DefinePlugin ────────────────────────────────────────────

WEBPACK_DEFINE = re.compile(
    r'new\s+webpack\.DefinePlugin\s*\(\s*\{([^}]+)\}',
    re.S
)
DEFINE_ENTRY = re.compile(r'["\']?([A-Z_][A-Z_0-9.]*)["\']?\s*:\s*(?:JSON\.stringify\s*\(\s*)?["\']([^"\']+)["\']')


def extract_framework_endpoints(text: str, line_of_func) -> list:
    """Extract endpoints from framework-specific patterns."""
    results = []
    seen = set()
    for pat, label in FRAMEWORK_ENDPOINT_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1)
            if val and val not in seen and len(val) > 2:
                seen.add(val)
                results.append({
                    'value': val,
                    'line': line_of_func(m.start()),
                    'type': label,
                    'source_framework': label,
                })
    return results


def extract_env_vars(text: str, line_of_func) -> list:
    """Extract environment variable references."""
    results = []
    seen = set()
    for pat, label in ENV_VAR_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1)
            if val and val not in seen:
                seen.add(val)
                # Check if there's a default value (|| "default" or ?? "default")
                ctx = text[m.end():m.end()+50]
                has_default = bool(re.match(r'\s*(?:\|\||&&|\?\?)\s*["\']', ctx))
                results.append({
                    'value': f"{label}: {val}" + (" (no default)" if not has_default else ""),
                    'line': line_of_func(m.start()),
                    'type': label,
                    'has_default': has_default,
                    'env_risk': not has_default,
                })
    return results


def extract_webpack_defines(text: str, line_of_func) -> list:
    """Extract Webpack DefinePlugin definitions."""
    results = []
    for m in WEBPACK_DEFINE.finditer(text):
        block = m.group(1)
        for entry in DEFINE_ENTRY.finditer(block):
            key, val = entry.group(1), entry.group(2)
            results.append({
                'value': f"DefinePlugin: {key} = {val}",
                'line': line_of_func(m.start()),
                'type': 'Webpack DefinePlugin',
            })
    return results
