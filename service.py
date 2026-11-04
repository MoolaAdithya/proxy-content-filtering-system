#!/usr/bin/env python3
"""Member 1 backend service (runs on h3). Threaded HTTP server.

  python3 service.py            # listens on 0.0.0.0:80 (proxy's default backend)
  python3 service.py 9000       # custom port
"""
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80


http.server.ThreadingHTTPServer.request_queue_size = 256   # default 5 drops SYNs under load


class Handler(http.server.BaseHTTPRequestHandler):
    def _reply(self, send_body=True):
        body = ('hello from backend\npath: %s\n' % self.path).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_GET(self):
        self._reply()

    def do_HEAD(self):
        self._reply(False)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        self._reply()

    def log_message(self, fmt, *args):
        print('%s %s' % (self.client_address[0], fmt % args), flush=True)


if __name__ == '__main__':
    print('backend service on port %d' % PORT, flush=True)
    http.server.ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
