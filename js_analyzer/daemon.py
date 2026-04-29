#!/usr/bin/env python3
"""
Enhancement #8 — Integration: Daemon Mode

HTTP daemon that listens for POST requests containing a file/URL,
runs analysis, and returns JSON results.
"""

import json
import os
import sys
import http.server
import threading
from typing import Optional


def start_daemon(port: int = 8080, analyzer_func=None):
    """
    Start HTTP daemon on the given port.
    analyzer_func(target: str) -> dict  should be the analysis function.
    """
    if analyzer_func is None:
        print("No analyzer function provided.")
        return

    class DaemonHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == '/analyze':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                try:
                    data = json.loads(body)
                    target = data.get('target', '')
                    options = data.get('options', {})
                    if not target:
                        self._send_json(400, {'error': 'Missing "target" field'})
                        return
                    result = analyzer_func(target, options)
                    self._send_json(200, result)
                except json.JSONDecodeError:
                    self._send_json(400, {'error': 'Invalid JSON'})
                except Exception as e:
                    self._send_json(500, {'error': str(e)})
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
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))

        def log_message(self, format, *args):
            sys.stderr.write(f"[daemon] {args[0]} {args[1]} {args[2]}\n")

    server = http.server.HTTPServer(('0.0.0.0', port), DaemonHandler)
    print(f"JS Analyzer daemon listening on http://0.0.0.0:{port}")
    print(f"  POST /analyze  — Analyze a target")
    print(f"  GET  /health   — Health check")
    print(f"Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("\nDaemon stopped.")
