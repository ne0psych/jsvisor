"""
HTTP Daemon Mode

Listens for POST requests with analysis targets. Validates input,
binds to localhost by default, and limits request body size.
"""

import json
import logging
import os
import sys
import http.server
from pathlib import Path

log = logging.getLogger("js_analyzer.daemon")

MAX_BODY_SIZE = 1024 * 1024  # 1 MB


def start_daemon(port: int = 8080, analyzer_func=None, bind="127.0.0.1"):
    """Start HTTP daemon on the given port. Binds to localhost for safety."""
    if analyzer_func is None:
        log.error("No analyzer function provided")
        return

    class DaemonHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == '/analyze':
                length = int(self.headers.get('Content-Length', 0))
                if length > MAX_BODY_SIZE:
                    self._send_json(413, {'error': 'Request body too large'})
                    return
                body = self.rfile.read(length).decode('utf-8', errors='replace')
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    self._send_json(400, {'error': 'Invalid JSON'})
                    return
                target = data.get('target', '')
                if not target or not isinstance(target, str):
                    self._send_json(400, {'error': 'Missing or invalid "target"'})
                    return
                # Validate target path exists
                resolved = Path(target).resolve()
                if not resolved.exists():
                    self._send_json(400, {'error': f'Target not found: {target}'})
                    return
                try:
                    options = data.get('options', {})
                    if not isinstance(options, dict):
                        options = {}
                    result = analyzer_func(str(resolved), options)
                    self._send_json(200, result)
                except Exception as e:
                    log.exception("Analysis failed")
                    self._send_json(500, {'error': 'Internal analysis error'})
            elif self.path == '/health':
                self._send_json(200, {'status': 'ok'})
            else:
                self._send_json(404, {'error': 'Not found'})

        def do_GET(self):
            if self.path == '/health':
                self._send_json(200, {'status': 'ok', 'version': '4.0.0'})
            else:
                self._send_json(404, {'error': 'Use POST /analyze'})

        def _send_json(self, code, data):
            payload = json.dumps(data, indent=2).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):
            log.info("[%s] %s %s", args[0], args[1], args[2] if len(args) > 2 else "")

    server = http.server.HTTPServer((bind, port), DaemonHandler)
    print(f"JSVisor daemon: http://{bind}:{port}")
    print(f"  POST /analyze  -- Analyze a target")
    print(f"  GET  /health   -- Health check")
    print(f"Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("\nDaemon stopped.")
