# JS Analyzer — Advanced JavaScript Security Scanner

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A powerful, extensible JavaScript static analysis tool that extracts **endpoints, secrets, URLs, emails, files, source maps, cloud resources, debug artifacts, GraphQL operations, and internal network indicators** from JavaScript source code.

Features a beautiful **Textual TUI**, generates **JSON / HTML / SARIF / Postman / Markdown** reports, supports **AST-based parsing**, **entropy-based secret detection**, **framework-aware analysis**, and much more.

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Advanced Dynamic Analysis** | AST parsing via `esprima`, string deobfuscation (`\xHH`, `\uXXXX`, `atob`/`btoa`), trivial expression evaluation |
| 2 | **Better Secret Detection** | Shannon entropy scoring, context-aware confidence, JWT/admin credential detection, AWS key validation |
| 3 | **Framework Detection** | React/Vue/Angular/Next.js/Nuxt/jQuery/Axios pattern recognition |
| 4 | **Network Discovery** | Relative→absolute URL resolution, API version bruteforce lists, GraphQL introspection, Swagger/OpenAPI detection |
| 5 | **Repo & Dependency Analysis** | `package.json` parsing, `process.env` risk detection, `.git` metadata extraction |
| 6 | **Rich Reporting** | HTML (with search/filter/copy), SARIF, Postman collection, Markdown summary, enhanced deduplication |
| 7 | **Performance** | Multi-threaded scanning, incremental cache (SHA-256), `.gitignore` support, streaming for large files |
| 8 | **Integration** | Daemon mode (HTTP API), GitHub Action template, pre-commit hook, Slack/Teams notifications |
| 9 | **TUI Enhancements** | Real-time search bar, collapsible file tree, multi-format export dialog, progress bar |
| 10 | **Security Hardening** | Secret auto-redaction, password-protected ZIP export, `--no-network`, `--redact` flag |
| 11 | **Additional Artifacts** | WebAssembly detection, browser storage keys, CORS misconfiguration, CDN/cloud provider summary |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/js-analyzer.git
cd js-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `textual` | Terminal UI framework |
| `esprima` | JavaScript AST parsing |
| `pathspec` | `.gitignore` pattern matching |
| `pycryptodome` | Password-protected ZIP export |
| `rich` | Rich text rendering (installed with textual) |

---

## Usage

### Interactive TUI (default)

```bash
python js_analyzer.py
```

### CLI Mode

```bash
# Single file
python js_analyzer.py -f app.bundle.js -o report

# Remote URL
python js_analyzer.py -u https://example.com/main.js -o report

# Directory scan (multi-threaded)
python js_analyzer.py -d ./src --threads 8 -o report

# With all enhancements enabled
python js_analyzer.py -d ./project \
  --ast \
  --entropy \
  --frameworks \
  --base-url https://api.example.com \
  --threads 8 \
  --format json html sarif postman markdown \
  -o analysis_report
```

### New CLI Flags

| Flag | Description |
|------|-------------|
| `--ast` | Enable AST-based analysis (requires `esprima`) |
| `--entropy` | Enable Shannon entropy scoring for secret detection |
| `--frameworks` | Enable framework-specific pattern detection |
| `--base-url URL` | Base URL for resolving relative endpoints |
| `--graphql-introspect` | Perform GraphQL introspection if endpoint found |
| `--threads N` | Thread count for directory scanning (default: 4) |
| `--incremental` | Skip unchanged files (uses `.js_analyzer_cache.json`) |
| `--respect-gitignore` | Respect `.gitignore` patterns |
| `--format FMT [FMT ...]` | Output formats: `json`, `html`, `sarif`, `postman`, `markdown` |
| `--daemon` | Start HTTP daemon mode |
| `--daemon-port PORT` | Daemon port (default: 8080) |
| `--redact` | Redact secrets in reports |
| `--no-network` | Disable all remote fetches |
| `--encrypt` | Create password-protected ZIP of reports |
| `--password PWD` | Password for encrypted ZIP |
| `--notify-webhook URL` | Slack/Teams webhook URL for notifications |

---

## Output Formats

### HTML Report
Beautiful, interactive single-file report with search/filter, copy-to-clipboard, and dark theme.

### SARIF
GitHub Code Scanning compatible format for CI/CD integration.

### Postman Collection
Import directly into Postman — all discovered endpoints as a ready-to-use collection.

### Markdown Summary
Risk-prioritized summary: Critical → High → Medium → Low.

---

## Integration

### GitHub Action

Copy `.github/workflows/js-analyzer.yml` to your repository:

```yaml
# See templates/github-action.yml for full template
```

### Pre-commit Hook

```bash
python js_analyzer.py --install-hook
# or manually copy templates/pre-commit to .git/hooks/pre-commit
```

### Daemon Mode

```bash
python js_analyzer.py --daemon --daemon-port 8080

# Send analysis requests
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "./src/app.js"}'
```

---

## Architecture

```
js_analyzer.py          ← Main entry point (backward compatible)
js_analyzer/
├── __init__.py
├── core.py             ← JSAnalyzer engine + patterns
├── ast_analyzer.py     ← AST-based analysis (esprima)
├── entropy.py          ← Shannon entropy + secret validation
├── frameworks.py       ← Framework-specific detection
├── network.py          ← Network discovery + GraphQL introspection
├── repo_analysis.py    ← Package.json, .git, dependency analysis
├── exporters.py        ← SARIF, Postman, Markdown exporters
├── performance.py      ← Threading, caching, gitignore
├── daemon.py           ← HTTP daemon mode
├── notifications.py    ← Slack/Teams webhook notifications
├── security.py         ← Redaction, encryption
├── artifacts.py        ← WASM, storage, CORS, CDN detection
├── tui.py              ← Enhanced Textual TUI
└── html_report.py      ← Enhanced HTML report generator
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
