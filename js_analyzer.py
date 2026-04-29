#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSVisor v4.0 -- Advanced JavaScript Security Scanner

Static analysis tool for JavaScript source files. Extracts endpoints,
URLs, secrets, emails, files, source maps, cloud identifiers, debug
artifacts, GraphQL operations, and internal network indicators.
"""


from __future__ import annotations

import re
import sys
import os
import json
import logging
import http.server
import threading
import webbrowser
import datetime
import argparse
import shutil
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError
from collections import defaultdict
from typing import Optional

log = logging.getLogger("js_analyzer")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB hard limit
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})




# =================================================================
#  Module imports
# =================================================================

try:
    from js_analyzer.ast_analyzer import (
        deobfuscate, extract_endpoints_ast, HAS_ESPRIMA,
    )
except ImportError:
    HAS_ESPRIMA = False
    def deobfuscate(t): return t
    def extract_endpoints_ast(s): return []

try:
    from js_analyzer.entropy import (
        shannon_entropy, is_high_entropy, assess_confidence,
        validate_secret_format, find_jwt_secrets,
        find_admin_credentials, find_high_entropy_strings,
    )
except ImportError:
    def shannon_entropy(s): return 0.0
    def is_high_entropy(s, t=4.5): return False
    def assess_confidence(v, l, la): return 'medium'
    def validate_secret_format(v, l): return None
    def find_jwt_secrets(t, f): return []
    def find_admin_credentials(t, f): return []
    def find_high_entropy_strings(t, f): return []

try:
    from js_analyzer.frameworks import (
        detect_frameworks, extract_framework_endpoints,
        extract_env_vars, extract_webpack_defines,
    )
except ImportError:
    def detect_frameworks(t): return []
    def extract_framework_endpoints(t, f): return []
    def extract_env_vars(t, f): return []
    def extract_webpack_defines(t, f): return []

try:
    from js_analyzer.network import (
        detect_swagger_refs, resolve_endpoints,
        detect_api_versions, perform_graphql_introspection,
    )
except ImportError:
    def detect_swagger_refs(t, f): return []
    def resolve_endpoints(e, b): return e
    def detect_api_versions(e): return {}
    def perform_graphql_introspection(u, n=False): return None

try:
    from js_analyzer.repo_analysis import (
        parse_package_json, check_vulnerable_deps,
        find_env_injection_risks, extract_git_info,
    )
except ImportError:
    def parse_package_json(r): return None
    def check_vulnerable_deps(p): return []
    def find_env_injection_risks(t, f): return []
    def extract_git_info(r): return None

try:
    from js_analyzer.performance import (
        collect_js_files_enhanced, scan_files_threaded,
        save_cache, read_file_streaming,
    )
except ImportError:
    pass  # fallback to built-in collect_js_files

try:
    from js_analyzer.artifacts import (
        detect_wasm, detect_browser_storage,
        detect_cors_misconfig, summarize_cdn_usage,
    )
except ImportError:
    def detect_wasm(t, f): return []
    def detect_browser_storage(t, f): return []
    def detect_cors_misconfig(t, f): return []
    def summarize_cdn_usage(t): return {}

try:
    from js_analyzer.security import (
        redact_secret, redact_findings, create_encrypted_zip,
        redact_console_output,
    )
except ImportError:
    def redact_secret(v, f=False): return v[:4]+'...'+v[-4:] if len(v)>12 else v
    def redact_findings(f, r=False): return f
    def create_encrypted_zip(fp, o, p=None): return o
    def redact_console_output(t): return t

try:
    from js_analyzer.exporters import (
        generate_sarif, generate_postman_collection,
        generate_markdown_summary, deduplicate_findings,
    )
except ImportError:
    def generate_sarif(f, t): return {}
    def generate_postman_collection(f, b=''): return {}
    def generate_markdown_summary(f, t, m=None): return ''
    def deduplicate_findings(f): return f

try:
    from js_analyzer.notifications import notify
except ImportError:
    def notify(f, t, n=False): pass

try:
    from js_analyzer.daemon import start_daemon
except ImportError:
    def start_daemon(p=8080, a=None): print('Daemon module not found.')

from js_analyzer.html_report import generate_html_report as _html_report_impl

# =================================================================
#  PATTERNS
# =================================================================

ENDPOINT_PATTERNS = [
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/webhook[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/health[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/status[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/metrics[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/swagger[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/openapi[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/docs?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/user[s]?/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/account[s]?/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/payment[s]?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/checkout[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/cart[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/search[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/report[s]?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/export[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/import[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/reset[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/verify[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/confirm[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/invite[s]?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/register[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/signup[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/profile[s]?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/settings?[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/2fa[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/mfa[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/saml[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/sso[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/callback[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/redirect[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/proxy[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/socket[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/ws[a-zA-Z0-9/_-]*)["\']', re.I),
    # API versioning patterns
    re.compile(r'["\'](/v[0-9]+(?:\.[0-9]+)?/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/graphi?ql[/]?)["\']', re.I),

    # Common framework endpoints
    re.compile(r'["\'](/wp-json/(?:wp/)?[a-zA-Z0-9/_-]+)["\']', re.I),          # WordPress REST API
    re.compile(r'["\'](/api/(?:rest|v[0-9])?/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/index\.php\?[a-zA-Z0-9_=/-]+)["\']'),                    # PHP query endpoints
    re.compile(r'["\'](/cgi-bin/[a-zA-Z0-9_/.-]+)["\']', re.I),                  # CGI scripts
    re.compile(r'["\'](/(?:api|rest|graphql)/[a-z0-9]+)["\']'),                  # short forms

    # Legacy/Admin endpoints
    re.compile(r'["\'](/server-status[/]?)["\']'),                               # Apache status
    re.compile(r'["\'](/phpmyadmin[/]?)["\']'),
    re.compile(r'["\'](/\.env[/]?)["\']'),
    re.compile(r'["\'](/\.git/(?:HEAD|config|index)[/]?)["\']'),
    re.compile(r'["\'](/actuator[/]?[a-zA-Z0-9/_-]*)["\']'),                    # Spring Boot actuator
    re.compile(r'["\'](/swagger-ui[/]?|/api-docs[/]?)["\']'),                    # OpenAPI docs

    # Cloud function endpoints
    re.compile(r'["\'](/.netlify/functions/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/.vercel/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/api/[a-zA-Z0-9-]+-(?:prod|dev|staging)/)["\']'),
    
]

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfront\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.supabase\.co[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.neon\.tech[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.vercel\.app[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.netlify\.app[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.railway\.app[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.render\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.ngrok\.io[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.ngrok-free\.app[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.azurewebsites\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.appspot\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.run\.app[^\s"\'<>]*)'),
        # More cloud services
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.digitaloceanspaces\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.backblazeb2\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.wasabisys\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.linodeobjects\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.r2\.cloudflarestorage\.com[^\s"\'<>]*)'),

    # CI/CD and hosting
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.gitlab\.io[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.github\.io[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.herokuapp\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.fly\.dev[^\s"\'<>]*)'),

    # Internal service URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.internal:[0-9]{4,5}[^\s"\'<>]*)'),
    re.compile(r'(https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?[^\s"\'<>]*)'),  # raw IP URLs

    # Monitoring & logging
    re.compile(r'(https?://(?:logs|metrics|monitoring)\.[a-zA-Z0-9.-]+\.[a-z]{2,}[^\s"\'<>]*)'),

]

SECRET_PATTERNS = [
        # OAuth & Token artifacts
    (re.compile(r'(refresh_token["\s:=]+["\']?([a-zA-Z0-9\-_.=]+)["\']?)', re.I), "OAuth Refresh Token"),
    (re.compile(r'(id_token["\s:=]+["\']?([a-zA-Z0-9\-_.=]+)["\']?)', re.I),      "OAuth ID Token"),
    (re.compile(r'(access_token["\s:=]+["\']?([a-zA-Z0-9\-_.=]+)["\']?)', re.I),  "OAuth Access Token"),
    (re.compile(r'(state["\s:=]+["\']?([a-zA-Z0-9\-_.=]{16,})["\']?)', re.I),     "OAuth State Parameter"),
    (re.compile(r'(AKIA[0-9A-Z]{16})'),                                                           "AWS Access Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'),                                                    "Google API Key"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'),                                                  "Stripe Live Secret"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'),                                                  "Stripe Live Publishable"),
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'),                                                  "Stripe Test Secret"),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'),                                                       "GitHub PAT"),
    (re.compile(r'(github_pat_[0-9a-zA-Z_]{82})'),                                               "GitHub Fine-Grained PAT"),
    (re.compile(r'(gho_[0-9a-zA-Z]{36})'),                                                       "GitHub OAuth Token"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'),                                          "Slack Token"),
    (re.compile(r'(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)'),                                         "Slack App Token"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'),           "JWT Token"),
    (re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)'),                         "Private Key"),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'),                                           "MongoDB URI"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'),                                             "PostgreSQL URI"),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'),                                         "Algolia Admin Key"),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'),                                         "Algolia App ID"),
    (re.compile(r'(mysql://[a-z0-9._%+\-]+:[^\s:@]+@[a-z0-9.-]+(?::\d{2,5})?(?:/[^\s"\'?]*)?)'), "MySQL URI"),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'),              "Facebook App ID"),
    (re.compile(r'(E--CEdEose0cBA[A-Z0-9]{20,})\b'),                                            "Facebook Access Token"),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'),                                                "Google OAuth2 Token"),
    (re.compile(r'(\d{9}:[a-zA-Z0-9_-]{35})'),                                                  "Telegram Bot Token"),
    (re.compile(r'(lin_api_[a-zA-Z0-9]{40})'),                                                  "Linear API Key"),
    (re.compile(r'(dop_v1_[a-z0-9]{64})'),                                                      "DigitalOcean Token"),
    (re.compile(r'(SG\.[\w\d\-_]{22}\.[\w\d\-_]{43})'),                                        "SendGrid API Key"),
    (re.compile(r'(glpat-[0-9a-zA-Z\-_]{20})'),                                                 "GitLab Token"),
    (re.compile(r'(shpat_[0-9a-fA-F]{32})'),                                                    "Shopify Access Token"),
    (re.compile(r'(NRII-[a-zA-Z0-9]{20,})'),                                                    "New Relic Key"),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'),                                                 "Stripe Restricted Key"),
    (re.compile(r'(whsec_[0-9a-zA-Z]{32,})'),                                                   "Stripe Webhook Secret"),
    (re.compile(r'(key-[a-z0-9]{32})'),                                                         "Mailgun API Key"),
    (re.compile(r'(re_[a-zA-Z0-9_]{16,})'),                                                     "Resend API Key"),
    (re.compile(r'(sk-[a-zA-Z0-9]{20,})'),                                                      "OpenAI API Key"),
    (re.compile(r'(sk-ant-[a-zA-Z0-9\-_]{80,})'),                                               "Anthropic API Key"),
    (re.compile(r'(r8_[a-zA-Z0-9]{32,})'),                                                      "Replicate API Token"),
    (re.compile(r'(pplx-[a-zA-Z0-9]{48})'),                                                     "Perplexity API Key"),
    (re.compile(r'(?i)(?:x-api-key|api.?key|apikey)["\s:=]+["\']([a-zA-Z0-9\-_.]{16,})["\']'), "Generic API Key"),
    (re.compile(r'(?i)(?:password|passwd|pwd)["\s:=]+["\']([^"\']{8,})["\']'),                  "Hardcoded Password"),
    (re.compile(r'(?i)(?:secret|client.?secret)["\s:=]+["\']([a-zA-Z0-9\-_.]{16,})["\']'),     "Client Secret"),
    (re.compile(r'(?i)(?:access.?token|auth.?token)["\s:=]+["\']([a-zA-Z0-9\-_.]{16,})["\']'), "Access Token"),
    (re.compile(r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'),  "HS256 JWT"),
    (re.compile(r'(?i)sentry.{0,32}dsn.{0,32}(https://[a-z0-9]+@o\d+\.ingest\.sentry\.io/\d+)'), "Sentry DSN"),
    (re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)'),  "Slack Webhook"),
    (re.compile(r'(https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+)'),            "Discord Webhook"),
    # Cloud provider keys
    (re.compile(r'(ASIA[0-9A-Z]{16})'),                                           "AWS Temporary Key (ASIA)"),
    (re.compile(r'(aws_secret_access_key["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?)', re.I), "AWS Secret Key"),
    (re.compile(r'(google_application_credentials["\s:=]+["\']?([^"\']+\.json)["\']?)', re.I), "GCP Credentials File"),
    (re.compile(r'(?:PRIVATE KEY-----.*?END (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----)', re.DOTALL), "Private Key (Multi-line)"),

    # Database connection strings -- more formats
    (re.compile(r'(postgresql://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+/\w+)'),      "PostgreSQL URI with password"),
    (re.compile(r'(mysql://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+/\w+)'),            "MySQL URI with password"),
    (re.compile(r'(mongodb://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+(?:/\w+)?)'),    "MongoDB URI with password"),
    (re.compile(r'(redis://:[^\s"\'<>]+@[^\s"\'<>]+(?:/\d+)?)'),                 "Redis URI with password"),
    (re.compile(r'(clickhouse://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+)'),          "ClickHouse URI"),

    # API keys for services
    (re.compile(r'(X-API-Key["\s:=]+["\']?([a-zA-Z0-9\-_.]{20,})["\']?)', re.I), "API Key Header"),
    (re.compile(r'(Bearer["\s:=]+["\']?([a-zA-Z0-9\-_.=]{20,})["\']?)', re.I),   "Bearer Token"),
    (re.compile(r'(Authorization["\s:=]+["\']?(Basic [a-zA-Z0-9=]+)["\']?)', re.I), "Basic Auth Credentials"),
    (re.compile(r'(twilio_api_key["\s:=]+["\']?([A-Za-z0-9]{32})["\']?)', re.I), "Twilio API Key"),
    (re.compile(r'(twilio_account_sid["\s:=]+["\']?([A-Za-z0-9]{34})["\']?)', re.I), "Twilio Account SID"),

    # More generic
    (re.compile(r'(client_id["\s:=]+["\']?([a-zA-Z0-9\-_.]{16,})["\']?)', re.I), "Client ID"),
    (re.compile(r'(tenant_id["\s:=]+["\']?([0-9a-f-]{36})["\']?)', re.I),       "Azure Tenant ID"),
    (re.compile(r'(subscription_id["\s:=]+["\']?([0-9a-f-]{36})["\']?)', re.I), "Azure Subscription ID"),
    # Webhooks
    (re.compile(r'(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+)'), "Microsoft Teams Webhook"),
]

EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'
    r'txt|log|conf|config|cfg|ini|env|'
    r'bak|backup|old|orig|copy|'
    r'key|pem|crt|cer|p12|pfx|jks|'
    r'doc|docx|pdf|'
    r'zip|tar|gz|rar|7z|'
    r'sh|bat|ps1|py|rb|pl|php|aspx?|jsp'
    r'))["\']',
    re.IGNORECASE,
)

SOURCEMAP_PATTERNS = [
    re.compile(r'//[#@]\s*sourceMappingURL=([^\s"\';\)]+)'),
    re.compile(r'["\']([a-zA-Z0-9_/.-]+\.js\.map)["\']'),
]

CLOUD_PATTERNS = [
    (re.compile(r'(arn:aws:[a-z0-9]+:[a-z0-9-]*:\d*:[a-zA-Z0-9:/._-]+)'),           "AWS ARN"),
    (re.compile(r'["\']([a-z0-9-]{3,63}\.s3\.amazonaws\.com)["\']'),                 "S3 Bucket"),
    (re.compile(r's3://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])'),                        "S3 Bucket (s3://)"),
    (re.compile(r'(?i)(?:bucket|s3.?bucket)["\s:=]+["\']([a-z0-9\-]{3,63})["\']'),  "S3 Bucket Name"),
    (re.compile(r'projects/([a-z][a-z0-9\-]{4,28}[a-z0-9])/'),                      "GCP Project ID"),
    (re.compile(r'["\']([a-z0-9-]+)\.firebaseapp\.com["\']'),                        "Firebase App"),
    (re.compile(r'["\']([a-z0-9-]+)\.firebaseio\.com["\']'),                         "Firebase DB"),
    (re.compile(r'(?i)azure.{0,32}subscription.{0,16}([0-9a-f-]{36})'),              "Azure Subscription ID"),
    (re.compile(r'(?i)azure.{0,32}tenant.{0,16}([0-9a-f-]{36})'),                   "Azure Tenant ID"),
    (re.compile(r'["\']([a-z0-9-]+)\.cloudfront\.net["\']'),                     "CloudFront Distribution"),
    (re.compile(r'(arn:aws:lambda:[a-z0-9-]+:\d+:function:[a-zA-Z0-9_-]+)'),   "AWS Lambda ARN"),
    (re.compile(r'(arn:aws:ecs:[a-z0-9-]+:\d+:cluster/[a-zA-Z0-9_-]+)'),       "AWS ECS Cluster"),
    (re.compile(r'(arn:aws:iam::\d+:role/[a-zA-Z0-9_-]+)'),                      "AWS IAM Role"),
    (re.compile(r'(projects/[a-z][a-z0-9-]{4,28}/locations/[a-z0-9-]+/functions/[a-zA-Z0-9_-]+)'), "GCP Cloud Function"),

    # Kubernetes secrets references (often in JS configs)
    (re.compile(r'(kubectl create secret generic [a-zA-Z0-9_-]+ --from-literal=[a-zA-Z0-9_-]+=[^"\'\s]+)'), "K8s Secret Command"),
    (re.compile(r'(apiVersion: v1\nkind: Secret\nmetadata:\n  name: [a-zA-Z0-9_-]+)'), "K8s Secret Manifest (multi-line)"),
]

# =================================================================
DEBUG_PATTERNS = [
    (re.compile(r'(?i)//\s*SECURITY\s*[:\s]+(.{10,100})'), "SECURITY Comment", 1),
    (re.compile(r'(?i)//\s*WARNING\s*[:\s]+(.{10,100})'),  "WARNING Comment",  1),
    (re.compile(r'(?i)localStorage\.setItem\s*\(\s*["\']([a-zA-Z0-9_-]+)["\']'), "LocalStorage Write", 1),
    (re.compile(r'(?i)sessionStorage\.setItem\s*\(\s*["\']([a-zA-Z0-9_-]+)["\']'), "SessionStorage Write", 1),
    (re.compile(r'(?i)cookie\.(?:get|set|delete)\s*\(\s*["\']([a-zA-Z0-9_-]+)["\']'), "Cookie Operation", 1),
    (re.compile(r'(?i)console\.table\s*\(([^)]{10,100})\)'), "Console Table (could leak data)", 1),
    (re.compile(r'(?i)window\.open\s*\(\s*["\']([^"\']+)["\']'), "Window Open URL", 1),
    (re.compile(r'(?i)fetch\s*\(\s*["\']([^"\']+)["\']'), "Fetch URL (complements endpoints)", 1),
    (re.compile(r'(?i)XMLHttpRequest\.open\s*\(\s*["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']'), "XHR URL", 1),
    (re.compile(r'(?i)console\.(log|debug|info|warn|error)\s*\(([^)]{10,100})\)'), "Console Log", 2),
    (re.compile(r'(?i)\bdebugger\b'), "Debugger", 0),
    (re.compile(r'(?i)//\s*TODO[:\s]+(.{10,80})'), "TODO Comment", 1),
    (re.compile(r'(?i)//\s*FIXME[:\s]+(.{10,80})'), "FIXME Comment", 1),
    (re.compile(r'(?i)//\s*HACK[:\s]+(.{10,80})'), "HACK Comment", 1),
    (re.compile(r'(?i)process\.env\.([A-Z_]{3,})\b'), "Env Var Ref", 1),
]

GRAPHQL_PATTERNS = [
    re.compile(r'(?i)(?:query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{'),
    re.compile(r'(?i)(?:query|mutation)\s+(\w+)\s*\(\s*\$?\w+\s*:\s*\w+\s*\)\s*\{'),   # more structured
    re.compile(r'(?i)gql\s*`([^`]+)`'),                                                # gql tagged template
    re.compile(r'(?i)apollo\.(?:query|mutate)\s*\(\s*\{\s*(?:query|mutation):\s*gql`([^`]+)`'), # Apollo client
    re.compile(r'(?i)useQuery\s*\(\s*gql`([^`]+)`'),                                   # React hook
]

NETWORK_PATTERNS = [
    (re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),                 "Private IP (10.x)"),
    (re.compile(r'\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'),  "Private IP (172.x)"),
    (re.compile(r'\b(192\.168\.\d{1,3}\.\d{1,3})\b'),                    "Private IP (192.168.x)"),
    (re.compile(r'\b(127\.0\.0\.\d+)\b'),                                 "Loopback IP"),
    (re.compile(r'\b(localhost:\d{2,5})\b'),                              "Localhost Port"),
    (re.compile(r'["\']([a-z0-9-]+\.internal)["\']'),                     "Internal Hostname"),
    (re.compile(r'["\']([a-z0-9-]+\.local)["\']'),                        "mDNS Hostname"),
    (re.compile(r'["\']([a-z0-9-]+\.corp)["\']'),                         "Corp Hostname"),
    (re.compile(r'["\']([a-z0-9-]+\.intranet)["\']'),                     "Intranet Hostname"),
    (re.compile(r'\b(0\.0\.0\.0)\b'),                                               "Wildcard IP"),
    (re.compile(r'\b(169\.254\.\d{1,3}\.\d{1,3})\b'),                               "Link-local IP"),
    (re.compile(r'\b([fF][cCdD][0-9a-fA-F]{2,}:|fe80:)[0-9a-fA-F:]+'),            "IPv6 (link-local / unique local)"),
    (re.compile(r'["\'](https?://[a-zA-Z0-9.-]+\.local:[0-9]{2,5})["\']'),         "Local HTTPS"),
    (re.compile(r'["\']([a-zA-Z0-9_-]+\.internal:[0-9]{2,5})["\']'),               "Internal port"),
    (re.compile(r'["\'](https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5})["\']'), "IP+port URL"),
]

# =================================================================
#  NOISE FILTERS
# =================================================================

NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'openoffice.org', 'docs.oasis-open.org', 'ns.adobe.com',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

NOISE_ENDPOINT_PATTERNS = [
    re.compile(r'^/api$'),
    re.compile(r'^/v[0-9]+$'),
    re.compile(r'^/\?'),
    re.compile(r'^/\\u[0-9a-f]{4}'),   # Unicode escapes
    re.compile(r'^\{\{'),
    re.compile(r'^\.\.?/'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),
    re.compile(r'-xform$'),
    re.compile(r'^sha\d*$'),
    re.compile(r'^aes$|^des$|^md5$'),
    re.compile(r'^/[A-Z][a-z]+\s'),
    re.compile(r'^/[A-Z][a-z]+$'),
    re.compile(r'^\d+ \d+ R$'),
    re.compile(r'^xl/|^docProps/|^_rels/|^META-INF/'),
    re.compile(r'\.xml$'),
    re.compile(r'^worksheets/|^theme/'),
    re.compile(r'^webpack|^zone\.js$'),
    re.compile(r'^readable-stream/|^process/|^stream/'),
    re.compile(r'^buffer$|^events$|^util$|^path$'),
    re.compile(r'^\+|^\$\{|^#|^\?ref='),
    re.compile(r'^/[a-zA-Z]$'),
    re.compile(r'^http://$'),
    re.compile(r'_ngcontent'),
]


NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}

FILE_NOISE = {
    'package.json', 'tsconfig.json', 'webpack', 'babel',
    'eslint', 'prettier', 'node_modules', '.min.',
    'polyfill', 'vendor', 'chunk', 'bundle',
}

SECRET_NOISE = ('example', 'placeholder', 'your_', 'xxxx', 'dummy', 'changeme', 'insert')

# =================================================================
#  SAFE GROUP HELPER
# =================================================================

def _sg(m, idx: int) -> str:
    """Safe group: returns stripped match.group(idx), falls back to group(0)."""
    try:
        v = m.group(idx)
        return v.strip() if v else ""
    except IndexError:
        return m.group(0).strip()


# =================================================================
#  ANALYZER ENGINE  (with line-number tracking)
# =================================================================

class JSAnalyzer:
    """Core analysis engine with line-number tracking."""

    def __init__(self, options: Optional[dict] = None):
        self._seen: set = set()
        self.findings: defaultdict = defaultdict(list)
        self.options = options or {}
        self.detected_frameworks: list = []
        self.cdn_summary: dict = {}

    # =================================================================

    def _vld_endpoint(self, v: str) -> bool:
        if not v or len(v) < 3 or v in NOISE_STRINGS:
            return False
        for p in NOISE_ENDPOINT_PATTERNS:
            if p.search(v):
                return False
        if not v.startswith('/'):
            return False
        parts = v.split('/')
        return not (len(parts) < 2 or all(len(p) < 2 for p in parts if p))

    def _vld_url(self, v: str) -> bool:
        if not v or len(v) < 15:
            return False
        vl = v.lower()
        for d in NOISE_DOMAINS:
            if d in vl:
                return False
        if '{' in v or 'undefined' in vl or 'null' in vl:
            return False
        if vl.startswith('data:'):
            return False
        bad_ext = ('.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.ico', '.eot')
        return not any(vl.endswith(x) for x in bad_ext)

    def _vld_secret(self, v: str) -> bool:
        if not v or len(v) < 10:
            return False
        vl = v.lower()
        return not any(x in vl for x in SECRET_NOISE)

    def _vld_email(self, v: str) -> bool:
        if not v or '@' not in v:
            return False
        domain = v.split('@')[-1].lower()
        if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com', 'email.com'}:
            return False
        return not any(x in v.lower() for x in ('example', 'placeholder', 'noreply', 'no-reply'))

    def _vld_file(self, v: str) -> bool:
        if not v or len(v) < 3:
            return False
        vl = v.lower()
        if any(x in vl for x in FILE_NOISE):
            return False
        if vl.endswith('.map'):
            return False
        if vl.endswith('.json') and len(v.split('/')[-1]) <= 7:
            return False
        return True

    # internal add

    def _add(self, cat: str, value: str, source: str, line: int,
             extra: Optional[dict] = None):
        key = f"{cat}:{value}"
        if key in self._seen:
            return
        self._seen.add(key)
        entry = {"value": value, "source": source, "line": line}
        if extra:
            entry.update(extra)
        self.findings[cat].append(entry)

    # main entry point

    def analyze_text(self, text: str, source_name: str = "<memory>") -> dict:
        self.findings.clear()
        self._seen.clear()

        # Deobfuscation (always safe, improves detection)
        if self.options.get('ast') or self.options.get('deobfuscate', True):
            text = deobfuscate(text)

        # Build line-offset table for O(log n) line-number lookup
        offsets = [0]
        for ch in text:
            offsets.append(offsets[-1] + 1)
        # simpler: use str methods
        line_starts = [0]
        pos = text.find('\n')
        while pos != -1:
            line_starts.append(pos + 1)
            pos = text.find('\n', pos + 1)

        def line_of(char_pos: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= char_pos:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1  # 1-based

        # Endpoints regex original
        for pat in ENDPOINT_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1)
                if self._vld_endpoint(v):
                    self._add("endpoints", v, source_name, line_of(m.start()))

        # Endpoints (AST-enhanced)
        if self.options.get('ast') and HAS_ESPRIMA:
            for ep in extract_endpoints_ast(text):
                v = ep.get('value', '')
                if v and self._vld_endpoint(v):
                    self._add("endpoints", v, source_name,
                              ep.get('line', 0), {'type': ep.get('type', 'AST')})

        # =================================================================
        for pat in URL_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1) or m.group(0).strip()
                if self._vld_url(v):
                    self._add("urls", v, source_name, line_of(m.start()))

        # Secrets regex original
        for pat, label in SECRET_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1)
                if v and self._vld_secret(v):
                    masked = v[:10] + "..." + v[-4:] if len(v) > 20 else v
                    extra = {"type": label, "raw_len": len(v)}
                    # Entropy + confidence
                    if self.options.get('entropy'):
                        line_text = text.splitlines()[line_of(m.start())-1] if line_of(m.start()) <= len(text.splitlines()) else ''
                        extra['confidence'] = assess_confidence(v, line_text, label)
                        extra['entropy'] = round(shannon_entropy(v), 2)
                        validation = validate_secret_format(v, label)
                        if validation is False:
                            extra['confidence'] = 'low'
                            extra['validated'] = False
                    self._add("secrets", f"{label}: {masked}", source_name,
                              line_of(m.start()), extra)

        # JWT secrets + admin credentials + high-entropy
        if self.options.get('entropy'):
            for item in find_jwt_secrets(text, line_of):
                item['source'] = source_name
                self._add("secrets", item['value'], source_name,
                          item['line'], item)
            for item in find_admin_credentials(text, line_of):
                item['source'] = source_name
                self._add("secrets", item['value'], source_name,
                          item['line'], item)
            for item in find_high_entropy_strings(text, line_of):
                item['source'] = source_name
                self._add("secrets", item['value'], source_name,
                          item['line'], item)

        # =================================================================
        for m in EMAIL_PATTERN.finditer(text):
            v = _sg(m, 1)
            if self._vld_email(v):
                self._add("emails", v, source_name, line_of(m.start()))

        # =================================================================
        for m in FILE_PATTERNS.finditer(text):
            v = _sg(m, 1)
            if self._vld_file(v):
                self._add("files", v, source_name, line_of(m.start()))

        # Source maps
        for pat in SOURCEMAP_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1) or m.group(0).strip()
                if v and not v.startswith('data:'):
                    self._add("sourcemaps", v, source_name, line_of(m.start()))

        # =================================================================
        for pat, label in CLOUD_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1) or m.group(0).strip()
                if v and len(v) > 3:
                    self._add("cloud", f"{label}: {v}", source_name,
                              line_of(m.start()), {"type": label})

        # =================================================================
        for pat, label, grp in DEBUG_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, grp)
                if v and len(v) > 3:
                    short = (v[:80] + "...") if len(v) > 80 else v
                    self._add("debug", f"{label}: {short}", source_name,
                              line_of(m.start()), {"type": label})

        # =================================================================
        for pat in GRAPHQL_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1)
                if v:
                    self._add("graphql", v, source_name, line_of(m.start()))

        # =================================================================
        for pat, label in NETWORK_PATTERNS:
            for m in pat.finditer(text):
                v = _sg(m, 1) or m.group(0).strip()
                if v:
                    self._add("network", f"{label}: {v}", source_name,
                              line_of(m.start()), {"type": label})

        # =================================================================
        #  Extended analysis passes
        # =================================================================

        # Framework-specific endpoints
        if self.options.get('frameworks'):
            self.detected_frameworks = detect_frameworks(text)
            for item in extract_framework_endpoints(text, line_of):
                self._add("endpoints", item['value'], source_name,
                          item['line'], item)
            for item in extract_env_vars(text, line_of):
                self._add("debug", item['value'], source_name,
                          item['line'], item)
            for item in extract_webpack_defines(text, line_of):
                self._add("debug", item['value'], source_name,
                          item['line'], item)

        # Swagger/OpenAPI detection
        for item in detect_swagger_refs(text, line_of):
            self._add("endpoints", item['value'], source_name,
                      item['line'], item)

        # Environment injection risks
        for item in find_env_injection_risks(text, line_of):
            self._add("debug", item['value'], source_name,
                      item['line'], item)

        # Web ssembly
        for item in detect_wasm(text, line_of):
            self._add("debug", item['value'], source_name,
                      item['line'], item)

        # Browser storage keys
        for item in detect_browser_storage(text, line_of):
            self._add("debug", item['value'], source_name,
                      item['line'], item)

        # CORS misconfigurations
        for item in detect_cors_misconfig(text, line_of):
            self._add("network", item['value'], source_name,
                      item['line'], item)

        # CDN/cloud summary
        self.cdn_summary = summarize_cdn_usage(text)

        return dict(self.findings)


# =================================================================
#  I/O HELPERS
# =================================================================

def _validate_url(url: str) -> str:
    """Validate URL scheme and structure. Raises ValueError on failure."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    return url


def _validate_path(path: str) -> Path:
    """Resolve path and guard against traversal. Raises ValueError on failure."""
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    return resolved


def fetch_url(url: str) -> Optional[str]:
    """Fetch URL content with scheme validation and size limit."""
    try:
        _validate_url(url)
    except ValueError as exc:
        log.error("URL rejected: %s", exc)
        return None
    try:
        req = Request(url, headers={"User-Agent": "JSVisor/4.0"})
        with urlopen(req, timeout=15) as resp:
            data = resp.read(MAX_FILE_SIZE + 1)
            if len(data) > MAX_FILE_SIZE:
                log.warning("Response too large (>%d bytes), truncated: %s",
                            MAX_FILE_SIZE, url)
                data = data[:MAX_FILE_SIZE]
            return data.decode("utf-8", errors="ignore")
    except Exception as exc:
        log.error("Fetch failed: %s: %s", url, exc)
        return None


def read_file(path: str):
    """Read file with size guard and symlink check."""
    try:
        p = Path(path).resolve()
        if p.is_symlink():
            log.warning("Skipping symlink: %s", path)
            return None, path
        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            log.warning("File too large (%d bytes), skipped: %s", size, path)
            return None, path
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(), str(p)
    except Exception as exc:
        log.error("Read failed: %s: %s", path, exc)
        return None, path


def collect_js_files(root: str) -> list[Path]:
    """Collect .js files, excluding noise directories. Validates root path."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        log.error("Not a directory: %s", root)
        return []
    skip = {'node_modules', '.git', 'dist', '__pycache__', '.cache',
            'build', 'coverage', '.next', '.nuxt'}
    result = []
    for fp in root_path.rglob("*.js"):
        if not any(part in skip for part in fp.parts):
            result.append(fp)
    return sorted(result)



def print_results(findings: dict, verbose: bool = False):
    ORDER = [
        ("endpoints",  "Endpoints"),
        ("urls",       "URLs"),
        ("secrets",    "Secrets  [!]"),
        ("emails",     "Emails"),
        ("files",      "Files"),
        ("sourcemaps", "Source Maps"),
        ("cloud",      "Cloud Resources"),
        ("debug",      "Debug Artifacts"),
        ("graphql",    "GraphQL"),
        ("network",    "Internal Network"),
    ]
    total = 0
    for cat, title in ORDER:
        items = findings.get(cat, [])
        if items:
            print(f"\n=== {title} ({len(items)}) ===")
            for item in items:
                ln = item.get("line", "?")
                src = item.get("source", "")
                if verbose:
                    print(f"  [{src}:{ln}]  {item['value']}")
                else:
                    print(f"  {item['value']}")
            total += len(items)
    print(f"\nTotal: {total} finding(s)." if total else "\nNo findings.")




def export_report(findings: dict, target: str, file_count: int, out_base: str,
                   formats: list = None, redact: bool = False,
                   base_url: str = '', meta_extra: dict = None,
                   encrypt: bool = False, password: str = '') -> dict:
    """
    Write reports in requested formats. Returns dict of {format: path}.
    Backward compatible: defaults to JSON + HTML.
    """
    if formats is None:
        formats = ['json', 'html']

    # Apply deduplication
    findings = deduplicate_findings(findings)

    # Apply redaction if requested
    if redact:
        findings = redact_findings(findings, True)

    meta = {
        "scan_time":  datetime.datetime.now().isoformat(timespec="seconds"),
        "target":     target,
        "file_count": file_count,
    }
    if meta_extra:
        meta.update(meta_extra)

    paths = {}

    # JSON -- always produced
    if 'json' in formats:
        json_path = out_base + "_findings.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "findings": findings}, fh, indent=2)
        paths['json'] = json_path

    # HTML report
    if 'html' in formats:
        html_path = out_base + "_report.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(_html_report_impl(findings, meta))
        paths['html'] = html_path

    # SARIF
    if 'sarif' in formats:
        sarif_path = out_base + ".sarif"
        sarif_data = generate_sarif(findings, target)
        with open(sarif_path, "w", encoding="utf-8") as fh:
            json.dump(sarif_data, fh, indent=2)
        paths['sarif'] = sarif_path

    # Postman collection
    if 'postman' in formats:
        postman_path = out_base + "_postman.json"
        postman_data = generate_postman_collection(findings, base_url)
        with open(postman_path, "w", encoding="utf-8") as fh:
            json.dump(postman_data, fh, indent=2)
        paths['postman'] = postman_path

    # Markdown summary
    if 'markdown' in formats:
        md_path = out_base + "_summary.md"
        md_content = generate_markdown_summary(findings, target, meta)
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_content)
        paths['markdown'] = md_path

    # Encrypted ZIP
    if encrypt and paths:
        zip_path = out_base + "_reports.zip"
        create_encrypted_zip(list(paths.values()), zip_path, password or None)
        paths['zip'] = zip_path

    return paths


def serve_report(html_path: str, port: int = 7777):
    """Serve the HTML report on localhost and open browser."""
    directory = str(Path(html_path).parent.resolve())
    filename  = Path(html_path).name

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)
        def log_message(self, *a):
            pass  # silence access log

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/{filename}"
    print(f"\nReport server: {url}  (Ctrl+C to stop)\n")
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()


# =================================================================
#  TUI CATEGORIES
# =================================================================

CATEGORIES = {
    "endpoints":  ("Endpoints",        "#4fc1ff"),
    "urls":       ("URLs",             "#79c0ff"),
    "secrets":    ("Secrets",          "#ff7b72"),
    "emails":     ("Emails",           "#ffa657"),
    "files":      ("Files",            "#7ee787"),
    "sourcemaps": ("Source Maps",      "#d2a8ff"),
    "cloud":      ("Cloud",            "#56d364"),
    "debug":      ("Debug",            "#e3b341"),
    "graphql":    ("GraphQL",          "#bc8cff"),
    "network":    ("Network",          "#f85149"),
}

# =================================================================
# =================================================================
# =================================================================

TUI_CSS = """
/* Base */
Screen {
    background: #0d1117;
    layers: base overlay;
}

/* Top bar */
#topbar {
    dock: top;
    height: 4;
    background: #010409;
    border-bottom: solid #21262d;
    layout: horizontal;
    padding: 0 1;
    align: center middle;
}

#scan-badge {
    background: #1f3a5f;
    color: #388bfd;
    width: 8;
    height: 1;
    content-align: center middle;
    text-style: bold;
    margin-right: 1;
}

#inp {
    width: 1fr;
    background: #0d1117;
    color: #e6edf3;
    border: tall #30363d;
    margin-right: 1;
}

#inp:focus {
    border: tall #388bfd;
}

#btn-run {
    width: 12;
    background: #238636;
    color: #ffffff;
    border: tall #2ea043;
    text-style: bold;
}

#btn-run:hover  { background: #2ea043; }
#btn-run:disabled {
    background: #21262d;
    color: #484f58;
    border: tall #30363d;
}

#btn-exp {
    width: 10;
    background: #1c2128;
    color: #58a6ff;
    border: tall #30363d;
    margin-left: 1;
}
#btn-exp:hover  { background: #21262d; border: tall #58a6ff; }

#btn-srv {
    width: 10;
    background: #1c2128;
    color: #3fb950;
    border: tall #30363d;
    margin-left: 1;
}
#btn-srv:hover  { background: #21262d; border: tall #3fb950; }

#btn-clr {
    width: 8;
    background: #1c2128;
    color: #8b949e;
    border: tall #30363d;
    margin-left: 1;
}
#btn-clr:hover  { background: #21262d; color: #e6edf3; }

/* Body */
#body {
    layout: horizontal;
    height: 1fr;
}

/* Sidebar */
#sidebar {
    width: 26;
    background: #010409;
    border-right: solid #21262d;
    height: 100%;
    overflow-y: auto;
    padding: 1 0;
}

.side-section-hdr {
    color: #484f58;
    text-style: bold;
    padding: 0 2;
    height: 1;
    margin-bottom: 1;
}

.cat-btn {
    width: 100%;
    height: 1;
    background: transparent;
    color: #8b949e;
    border: none;
    text-align: left;
    content-align: left middle;
    padding: 0 2;
    margin: 0;
}

.cat-btn:hover    { background: #161b22; color: #e6edf3; }
.cat-btn.active   {
    background: #1c2128;
    color: #e6edf3;
    border-left: solid #388bfd;
}

/* Content area */
#content {
    width: 1fr;
    height: 100%;
    layout: vertical;
}

/* Findings panel */
#findings-wrap {
    height: 2fr;
    border: solid #21262d;
    border-title-color: #58a6ff;
    border-title-style: bold;
    margin: 1 1 0 1;
}

DataTable {
    height: 1fr;
    background: #0d1117;
    color: #e6edf3;
}

DataTable > .datatable--header {
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #1c2128;
    color: #e6edf3;
}

DataTable > .datatable--even-row {
    background: #0a0e14;
}

/* Log panel */
#log-wrap {
    height: 1fr;
    border: solid #21262d;
    border-title-color: #484f58;
    border-title-style: bold;
    margin: 1 1 0 1;
}

Log {
    height: 1fr;
    background: #0d1117;
    color: #484f58;
    padding: 0 1;
}

/* Status bar */
#statusbar {
    dock: bottom;
    height: 1;
    background: #010409;
    border-top: solid #21262d;
    layout: horizontal;
    padding: 0 2;
    align: center middle;
}

#status-lbl {
    width: 1fr;
    color: #484f58;
    content-align: left middle;
}

#keybinds {
    color: #30363d;
    content-align: right middle;
}
"""

# =================================================================
#  TUI APPLICATION
# =================================================================

def run_tui(initial_target: Optional[str] = None):
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Input, Button, DataTable, Static, Log
        from textual.containers import Horizontal, Vertical
        from textual.binding import Binding
        from textual import work
        from rich.text import Text
    except ImportError:
        print("Textual not installed.  Run:  pip install textual")
        sys.exit(1)

    class JSAnalyzerApp(App):
        TITLE = "JSVisor"
        CSS   = TUI_CSS
        BINDINGS = [
            Binding("ctrl+r", "run",        "Analyze", show=False),
            Binding("ctrl+e", "export",     "Export",  show=False),
            Binding("ctrl+s", "serve",      "Serve",   show=False),
            Binding("ctrl+l", "clear",      "Clear",   show=False),
            Binding("ctrl+h", "toggle_log", "Log",     show=False),
            Binding("ctrl+c", "quit",       "Quit",    show=False),
        ]

        def __init__(self, initial_target: Optional[str] = None):
            super().__init__()
            self._initial     = initial_target
            self._findings:   dict = {}
            self._active_cat: str  = "endpoints"
            self._scanning:   bool = False
            self._html_path:  Optional[str] = None
            self._file_count: int  = 0
            self._target:     str  = initial_target or ""

        # =================================================================

        def compose(self) -> ComposeResult:
            with Horizontal(id="topbar"):
                yield Static(" SCAN ", id="scan-badge")
                yield Input(
                    placeholder="File, URL, or directory ...",
                    id="inp",
                    value=self._initial or "",
                )
                yield Button("Analyze", id="btn-run")
                yield Button("Export",  id="btn-exp")
                yield Button("Serve",   id="btn-srv")
                yield Button("Clear",   id="btn-clr")

            with Horizontal(id="body"):
                with Vertical(id="sidebar"):
                    yield Static("CATEGORIES", classes="side-section-hdr")
                    for cat in CATEGORIES:
                        label, _ = CATEGORIES[cat]
                        yield Button(f"{label}  [0]", id=f"cat-{cat}", classes="cat-btn")

                with Vertical(id="content"):
                    with Vertical(id="findings-wrap"):
                        yield DataTable(id="dt", cursor_type="row", zebra_stripes=True)
                    with Vertical(id="log-wrap"):
                        yield Log(id="log", auto_scroll=True)

            with Horizontal(id="statusbar"):
                yield Static("Ready -- enter a target and press Ctrl+R", id="status-lbl")
                yield Static(
                    "^R Analyze  ^E Export  ^S Serve  ^L Clear  ^H Log  ^C Quit",
                    id="keybinds",
                )

        # =================================================================

        def on_mount(self) -> None:
            dt: DataTable = self.query_one("#dt", DataTable)
            dt.add_columns("Line", "Value", "Source")
            self._set_border_titles()
            self._highlight_cat(self._active_cat)
            self._write_log("JSVisor ready.  Enter a target and press Ctrl+R.")
            self._write_log("Supports: local .js file, remote URL, directory, project root.")

        def _set_border_titles(self):
            self.query_one("#findings-wrap").border_title = "Findings"
            self.query_one("#log-wrap").border_title      = "Log"

        # =================================================================

        def _highlight_cat(self, cat: str):
            for c in CATEGORIES:
                self.query_one(f"#cat-{c}", Button).remove_class("active")
            self.query_one(f"#cat-{cat}", Button).add_class("active")

        def _update_count(self, cat: str, n: int):
            label, _ = CATEGORIES[cat]
            self.query_one(f"#cat-{cat}", Button).label = f"{label}  [{n}]"

        # button dispatch

        def on_button_pressed(self, event: Button.Pressed) -> None:
            bid = event.button.id or ""
            if bid == "btn-run":
                self.action_run()
            elif bid == "btn-exp":
                self.action_export()
            elif bid == "btn-srv":
                self.action_serve()
            elif bid == "btn-clr":
                self.action_clear()
            elif bid.startswith("cat-"):
                cat = bid[4:]
                self._active_cat = cat
                self._highlight_cat(cat)
                self._populate_table(cat)

        # =================================================================

        def action_run(self) -> None:
            target = self.query_one("#inp", Input).value.strip()
            if not target:
                self._set_status("Enter a target first.")
                return
            if self._scanning:
                self._set_status("Scan already in progress.")
                return
            self._target  = target
            self._scanning = True
            self._html_path = None
            self._set_status("Scanning ...")
            self.query_one("#btn-run", Button).disabled = True
            self._do_scan(target)

        def action_export(self) -> None:
            if not self._findings:
                self._set_status("Nothing to export -- run a scan first.")
                return
            self._do_export()

        def action_serve(self) -> None:
            if not self._html_path:
                self._set_status("Export first, then Serve.")
                return
            self._set_status(f"Serving {self._html_path} on http://127.0.0.1:7777 ...")
            self._write_log("Opening browser ...")
            threading.Thread(
                target=serve_report,
                args=(self._html_path, 7777),
                daemon=True,
            ).start()

        def action_clear(self) -> None:
            self._findings = {}
            self._html_path = None
            self.query_one("#dt", DataTable).clear()
            for cat in CATEGORIES:
                self._update_count(cat, 0)
            self._set_status("Cleared.")
            self._write_log("Results cleared.")

        def action_toggle_log(self) -> None:
            lw = self.query_one("#log-wrap")
            lw.display = not lw.display

        # background scan

        @work(thread=True)
        def _do_scan(self, target: str) -> None:
            analyzer = JSAnalyzer()
            combined: dict = defaultdict(list)

            def merge(res: dict):
                for cat, items in res.items():
                    combined[cat].extend(items)

            try:
                if target.startswith(("http://", "https://")):
                    self.call_from_thread(self._write_log, f"Fetching: {target}")
                    content = fetch_url(target)
                    if content:
                        self.call_from_thread(self._write_log,
                            f"Received {len(content):,} bytes")
                        merge(analyzer.analyze_text(content, target))
                        self._file_count = 1
                    else:
                        self.call_from_thread(self._write_log, "Fetch failed.")

                elif os.path.isdir(target):
                    js_files = collect_js_files(target)
                    self._file_count = len(js_files)
                    self.call_from_thread(self._write_log,
                        f"Found {len(js_files)} JS file(s) in {target}")
                    for i, fp in enumerate(js_files, 1):
                        self.call_from_thread(self._write_log,
                            f"  [{i}/{len(js_files)}] {fp.name}")
                        content, src = read_file(str(fp))
                        if content:
                            merge(analyzer.analyze_text(content, src))

                elif os.path.isfile(target):
                    self.call_from_thread(self._write_log, f"Reading: {target}")
                    content, src = read_file(target)
                    if content:
                        self.call_from_thread(self._write_log,
                            f"Read {len(content):,} bytes")
                        merge(analyzer.analyze_text(content, src))
                        self._file_count = 1
                    else:
                        self.call_from_thread(self._write_log,
                            f"Could not read: {target}")
                else:
                    self.call_from_thread(self._write_log, f"Not found: {target}")
                    self.call_from_thread(self._set_status, f"Not found: {target}")
                    return

                self.call_from_thread(self._finish_scan, dict(combined))

            except Exception as exc:
                import traceback
                self.call_from_thread(self._write_log, f"ERROR: {exc}")
                self.call_from_thread(self._write_log, traceback.format_exc())
                self.call_from_thread(self._set_status, f"Error: {exc}")
            finally:
                self._scanning = False
                self.call_from_thread(
                    lambda: setattr(
                        self.query_one("#btn-run", Button), "disabled", False
                    )
                )

        # post scan

        def _finish_scan(self, findings: dict) -> None:
            self._findings = findings
            total = sum(len(v) for v in findings.values())
            sc    = len(findings.get("secrets", []))

            for cat in CATEGORIES:
                self._update_count(cat, len(findings.get(cat, [])))

            self._populate_table(self._active_cat)

            msg = f"Done -- {total} finding(s) across {self._file_count} file(s)."
            if sc:
                msg += f"  WARNING: {sc} secret(s) found."
            self._set_status(msg)
            self._write_log(msg)
            self._write_log("Press Ctrl+E to export JSON + HTML report.")

        def _populate_table(self, cat: str) -> None:
            dt: DataTable = self.query_one("#dt", DataTable)
            dt.clear()
            items = self._findings.get(cat, [])
            _, col_color = CATEGORIES.get(cat, ("", "#e6edf3"))

            self.query_one("#findings-wrap").border_title = (
                f"Findings -- {CATEGORIES[cat][0]}  ({len(items)})"
            )

            for item in items:
                ln  = str(item.get("line", "?"))
                val = Text(item["value"], style=col_color, overflow="ellipsis")
                src = Text(
                    Path(item.get("source", "")).name or item.get("source", ""),
                    style="#484f58",
                    overflow="ellipsis",
                )
                dt.add_row(ln, val, src)

        # =================================================================

        def _do_export(self) -> None:
            target   = self.query_one("#inp", Input).value.strip()
            out_base = Path(target).stem if target else "js_analysis"
            try:
                paths = export_report(
                    self._findings, target, self._file_count, out_base
                )
                self._html_path = paths.get('html')
                msg = "Exported: " + " | ".join(f"{k}: {v}" for k, v in paths.items())
                self._set_status(msg)
                for fmt, path in paths.items():
                    self._write_log(f"{fmt.upper()}: {path}")
                self._write_log("Press Ctrl+S to open report in browser.")
            except Exception as exc:
                self._set_status(f"Export failed: {exc}")
                self._write_log(f"Export error: {exc}")

        # =================================================================

        def _set_status(self, msg: str) -> None:
            try:
                lbl = self.query_one("#status-lbl", Static)
                if any(w in msg for w in ("WARNING", "Error", "failed", "Not found")):
                    lbl.update(f"[bold #ff7b72]{msg}[/]")
                elif "Done" in msg:
                    lbl.update(f"[bold #3fb950]{msg}[/]")
                elif any(w in msg for w in ("Scanning", "Fetching", "Reading")):
                    lbl.update(f"[#e3b341]{msg}[/]")
                else:
                    lbl.update(f"[#8b949e]{msg}[/]")
            except Exception:
                pass

        def _write_log(self, msg: str) -> None:
            try:
                self.query_one("#log", Log).write_line(msg)
            except Exception:
                pass

    JSAnalyzerApp(initial_target=initial_target).run()


# =================================================================
#  ENTRY POINT
# =================================================================

def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    p = argparse.ArgumentParser(
        description="JSVisor v4.0 -- Advanced JavaScript Security Scanner"
    )
    p.add_argument("-f", "--file",      help="Single local JS file")
    p.add_argument("-u", "--url",       help="Remote JS URL")
    p.add_argument("-d", "--directory", help="Directory to scan recursively")
    p.add_argument("-o", "--output",    help="Output base name")
    p.add_argument("-v", "--verbose",   action="store_true", help="Show file:line per finding")
    p.add_argument("--tui",            action="store_true",  help="Launch interactive TUI")
    p.add_argument("--serve",          action="store_true",  help="Serve HTML report in browser")
    p.add_argument("--port",           type=int, default=7777, help="Port for --serve")

    # Analysis options
    p.add_argument("--ast",            action="store_true", help="Enable AST-based analysis")
    p.add_argument("--entropy",        action="store_true", help="Enable entropy scoring for secrets")
    p.add_argument("--frameworks",     action="store_true", help="Enable framework detection")
    p.add_argument("--base-url",       default="", help="Base URL for resolving relative endpoints")
    p.add_argument("--graphql-introspect", action="store_true", help="Perform GraphQL introspection")

    # Output formats
    p.add_argument("--format",         nargs="+", default=["json", "html"],
                   choices=["json", "html", "sarif", "postman", "markdown"],
                   help="Output formats (default: json html)")

    # Performance
    p.add_argument("--threads",        type=int, default=4, help="Thread count for directory scanning")
    p.add_argument("--incremental",    action="store_true", help="Skip unchanged files (uses cache)")
    p.add_argument("--respect-gitignore", action="store_true", help="Respect .gitignore patterns")

    # Integration
    p.add_argument("--daemon",         action="store_true", help="Start HTTP daemon mode")
    p.add_argument("--daemon-port",    type=int, default=8080, help="Daemon port (default 8080)")
    p.add_argument("--notify-webhook", default="", help="Slack/Teams webhook URL for notifications")
    p.add_argument("--install-hook",   action="store_true", help="Install pre-commit hook")

    # Security
    p.add_argument("--redact",         action="store_true", help="Redact secrets in reports")
    p.add_argument("--no-network",     action="store_true", help="Disable all remote fetches")
    p.add_argument("--encrypt",        action="store_true", help="Create password-protected ZIP")
    p.add_argument("--password",       default="", help="Password for encrypted ZIP")

    # Verbosity
    p.add_argument("--debug",          action="store_true", help="Enable debug logging")

    args = p.parse_args()

    if args.debug:
        logging.getLogger("js_analyzer").setLevel(logging.DEBUG)

    # Install pre-commit hook
    if args.install_hook:
        hook_src = Path(__file__).parent / 'templates' / 'pre-commit'
        hook_dst = Path('.git') / 'hooks' / 'pre-commit'
        if hook_src.exists():
            hook_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(hook_src), str(hook_dst))
            print(f"Pre-commit hook installed: {hook_dst}")
        else:
            print(f"Template not found: {hook_src}")
        return

    # Daemon mode
    if args.daemon:
        def daemon_analyze(target, options=None):
            resolved = Path(target).resolve()
            if not resolved.exists():
                return {'error': f'Target not found: {target}'}
            opts = options or {}
            opts.update({'ast': args.ast, 'entropy': args.entropy,
                         'frameworks': args.frameworks})
            a = JSAnalyzer(options=opts)
            combined = defaultdict(list)
            if resolved.is_file():
                content, src = read_file(str(resolved))
                if content:
                    for cat, items in a.analyze_text(content, src).items():
                        combined[cat].extend(items)
            elif resolved.is_dir():
                for fp in collect_js_files(str(resolved)):
                    content, src = read_file(str(fp))
                    if content:
                        for cat, items in a.analyze_text(content, src).items():
                            combined[cat].extend(items)
            return {'findings': dict(combined),
                    'total': sum(len(v) for v in combined.values())}
        start_daemon(args.daemon_port, daemon_analyze)
        return

    # TUI mode (default when no input specified)
    if args.tui or not any([args.file, args.url, args.directory]):
        run_tui(initial_target=args.file or args.url or args.directory)
        return

    # CLI mode
    options = {
        'ast': args.ast,
        'entropy': args.entropy,
        'frameworks': args.frameworks,
    }
    analyzer = JSAnalyzer(options=options)
    all_finds: dict = defaultdict(list)
    file_count = 0

    def merge(res):
        for cat, items in res.items():
            all_finds[cat].extend(items)

    target = ""

    if args.file:
        target = args.file
        if args.no_network and args.file.startswith(('http://', 'https://')):
            log.error("--no-network prevents fetching URLs")
            sys.exit(1)
        content, src = read_file(args.file)
        if content:
            merge(analyzer.analyze_text(content, src))
            file_count = 1

    elif args.url:
        target = args.url
        if args.no_network:
            log.error("--no-network prevents fetching URLs")
            sys.exit(1)
        content = fetch_url(args.url)
        if content:
            merge(analyzer.analyze_text(content, args.url))
            file_count = 1

    elif args.directory:
        target = args.directory
        js_files, cache = collect_js_files_enhanced(
            args.directory,
            respect_gitignore=args.respect_gitignore,
            incremental=args.incremental,
        )
        if not js_files:
            print(f"No .js files found in {args.directory}")
            return

        print(f"Scanning {len(js_files)} file(s) with {args.threads} thread(s)...")

        if args.threads > 1:
            def scan_single(filepath):
                a = JSAnalyzer(options=options)
                content, src = read_file(filepath)
                if content:
                    return a.analyze_text(content, src)
                return {}
            result = scan_files_threaded(js_files, scan_single, args.threads)
            for cat, items in result.items():
                all_finds[cat].extend(items)
        else:
            for fp in js_files:
                content, src = read_file(str(fp))
                if content:
                    merge(analyzer.analyze_text(content, src))

        file_count = len(js_files)

        if args.incremental and cache:
            save_cache(args.directory, cache)

        pkg_info = parse_package_json(args.directory)
        if pkg_info:
            print(f"\nPackage: {pkg_info.get('name')} v{pkg_info.get('version')}")
            vulns = check_vulnerable_deps(pkg_info)
            if vulns:
                print(f"  WARNING: {len(vulns)} known vulnerable dependencies:")
                for v in vulns:
                    print(f"    {v['package']} {v['installed']} -- "
                          f"{v['cve']} ({v['severity']})")

        git_info = extract_git_info(args.directory)
        if git_info:
            branch = git_info.get('branch', '?')
            commit = git_info.get('commit', '?')
            print(f"  Git: {branch} @ {commit}")
            if git_info.get('exposed_config'):
                print("  WARNING: .git/config is exposed")

        print("Done.")

    findings = dict(all_finds)
    if not findings:
        print("No findings.")
        return

    if args.base_url and 'endpoints' in findings:
        findings['endpoints'] = resolve_endpoints(
            findings['endpoints'], args.base_url)

    if 'endpoints' in findings:
        ver_info = detect_api_versions(findings['endpoints'])
        if ver_info.get('versions_found'):
            print(f"\nAPI versions detected: {ver_info['versions_found']}")

    if args.redact:
        print_results(redact_findings(findings, True), args.verbose)
    else:
        print_results(findings, args.verbose)

    if args.output:
        meta_extra = {
            'frameworks': getattr(analyzer, 'detected_frameworks', []),
            'cdn_summary': getattr(analyzer, 'cdn_summary', {}),
        }
        paths = export_report(
            findings, target, file_count, args.output,
            formats=args.format, redact=args.redact,
            base_url=args.base_url, meta_extra=meta_extra,
            encrypt=args.encrypt, password=args.password,
        )
        print("\nExported:")
        for fmt, path in paths.items():
            print(f"  {fmt.upper():10s}: {path}")
        if args.serve and 'html' in paths:
            serve_report(paths['html'], args.port)
    elif args.serve:
        out_base = Path(target).stem if target else "js_analysis"
        paths = export_report(findings, target, file_count, out_base)
        if 'html' in paths:
            print(f"\nHTML : {paths['html']}")
            serve_report(paths['html'], args.port)

    if args.notify_webhook:
        os.environ['JSVISOR_SLACK_WEBHOOK'] = args.notify_webhook
    notify(findings, target, args.no_network)


if __name__ == "__main__":
    main()

