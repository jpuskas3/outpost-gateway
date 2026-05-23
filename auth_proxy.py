"""
Outpost Auth Proxy — Samsung Gateway
Native Python service on port 5000.
Zero external dependencies — pure stdlib.

Two-layer security:
  Layer 1 — /verify endpoint (called by nginx auth_request)
             Checks X-Outpost-Token header against stored hash.
             No token or wrong token = 401 → nginx returns 444 (silent drop).
             Valid token = 200 → nginx proxies request to this service.

  Layer 2 — /gateway/login (username + password)
             Only reachable after Layer 1 passes.
             Verifies credentials against Mac mini API.
             Issues session cookie on success.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from socketserver import ThreadingMixIn
import json
import os
import hmac
import hashlib
import base64
import time
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

OUTPOST_API    = os.environ.get('OUTPOST_API',    'http://192.168.0.107:8000')
OUTPOST_UI     = os.environ.get('OUTPOST_UI',     'http://192.168.0.107:8000')
SESSION_SECRET = os.environ.get('SESSION_SECRET', 'outpost-gateway-secret-change-me').encode()
COOKIE_NAME    = 'outpost_session'
SESSION_HOURS  = 24
PORT           = 5000

# Token hash file — written by push_token_to_gateway.sh on Mac mini
TOKEN_HASH_FILE = Path('/home/backup/outpost-gateway/token.hash')

# Paths that never require a session
PUBLIC_PREFIXES = ('static/', 'favicon.ico', 'gateway/')

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
<title>Outpost Access</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #111; color: #f0f0f0; font-family: -apple-system, Arial, sans-serif;
         display: flex; align-items: center; justify-content: center; height: 100vh; }
  .box { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 32px; width: 320px; }
  h2 { font-size: 16px; color: #009578; margin-bottom: 20px; }
  input { width: 100%; background: #111; border: 1px solid #333; border-radius: 4px;
          color: #f0f0f0; padding: 8px 10px; font-size: 13px; margin-bottom: 10px; }
  button { width: 100%; background: #009578; border: none; border-radius: 4px;
           color: white; padding: 10px; font-size: 13px; cursor: pointer; margin-top: 4px; }
  button:hover { background: #007a62; }
  .err { color: #ff4d4d; font-size: 12px; margin-top: 10px; text-align: center; }
</style>
</head>
<body>
<div class="box">
  <h2>Outpost Access</h2>
  <form method="POST" action="/gateway/login">
    <input type="text" name="username" placeholder="Username" autofocus>
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Connect</button>
  </form>
  ERROR_PLACEHOLDER
</div>
</body>
</html>"""

def render_login(error=''):
    return LOGIN_HTML.replace('ERROR_PLACEHOLDER', error)

# ── Token gate (Layer 1) ───────────────────────────────────────────────────────

def load_token_hash() -> dict | None:
    """Load the current valid token hash from disk."""
    if not TOKEN_HASH_FILE.exists():
        return None
    try:
        with open(TOKEN_HASH_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def verify_token(presented_token: str) -> tuple[bool, str]:
    """
    Hash the presented token and compare to stored hash.
    Returns (valid, username).
    """
    stored = load_token_hash()
    if not stored:
        logger.warning('Token hash file not found or unreadable — gate is CLOSED')
        return False, ''

    presented_hash = hashlib.sha256(presented_token.encode()).hexdigest()

    if hmac.compare_digest(presented_hash, stored.get('token_hash', '')):
        return True, stored.get('username', '')

    return False, ''

# ── Session cookie signing ─────────────────────────────────────────────────────

def sign_payload(payload):
    data = json.dumps(payload, separators=(',', ':')).encode()
    b64  = base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    sig  = hmac.new(SESSION_SECRET, b64.encode(), hashlib.sha256).hexdigest()
    return b64 + '.' + sig

def verify_payload(cookie):
    try:
        b64, sig = cookie.rsplit('.', 1)
        expected = hmac.new(SESSION_SECRET, b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data    = base64.urlsafe_b64decode(b64 + '==')
        payload = json.loads(data)
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def make_session_cookie(username, api_token):
    return sign_payload({
        'user':  username,
        'token': api_token,
        'exp':   time.time() + SESSION_HOURS * 3600
    })

# ── API call ───────────────────────────────────────────────────────────────────

def api_post(path, body):
    url  = OUTPOST_API + path
    data = json.dumps(body).encode()
    req  = Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {'error': str(e)}
    except URLError as e:
        logger.error('API error %s: %s', path, e)
        return 503, {'error': str(e)}
    except Exception as e:
        return 500, {'error': str(e)}

# ── Proxy ──────────────────────────────────────────────────────────────────────

SKIP_REQ_HEADERS  = {'host', 'content-length', 'transfer-encoding', 'connection'}
SKIP_RESP_HEADERS = {'transfer-encoding', 'connection', 'keep-alive', 'server'}

def proxy_to(target_url, handler, api_token=None):
    headers = {}
    for key, val in handler.headers.items():
        if key.lower() not in SKIP_REQ_HEADERS:
            headers[key] = val

    headers['X-Gateway']       = 'samsung'
    headers['X-Real-IP']       = handler.client_address[0]
    headers['X-Forwarded-For'] = handler.client_address[0]
    if api_token:
        headers['Authorization'] = 'Bearer ' + api_token

    length = int(handler.headers.get('Content-Length', 0))
    body   = handler.rfile.read(length) if length > 0 else None

    try:
        req = Request(target_url, data=body, headers=headers, method=handler.command)
        with urlopen(req, timeout=60) as resp:
            return resp.status, list(resp.headers.items()), resp.read()
    except HTTPError as e:
        try:
            return e.code, list(e.headers.items()), e.read()
        except Exception:
            return e.code, [], b'Upstream error'
    except URLError as e:
        logger.error('Proxy error %s: %s', target_url, e)
        return 503, [], b'Outpost unreachable'
    except Exception as e:
        logger.error('Proxy exception: %s', e)
        return 502, [], ('Gateway error: ' + str(e)).encode()

# ── Handler ───────────────────────────────────────────────────────────────────

class AuthProxyHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        logger.info('%s %s', self.client_address[0], fmt % args)

    def get_session(self):
        cookie_header = self.headers.get('Cookie', '')
        for part in cookie_header.split(';'):
            part = part.strip()
            if part.startswith(COOKIE_NAME + '='):
                return verify_payload(part[len(COOKIE_NAME)+1:])
        return None

    def send_full_response(self, status, headers_list, body):
        self.send_response(status)
        wrote_content_length = False
        for k, v in headers_list:
            if k.lower() in SKIP_RESP_HEADERS:
                continue
            if k.lower() == 'location':
                v = v.replace('http://192.168.0.107:8000', '') \
                     .replace('http://192.168.0.107', '') \
                     .replace('http://127.0.0.1:5000', '') \
                     .replace('http://127.0.0.1', '')
            if k.lower() == 'content-length':
                wrote_content_length = True
            try:
                self.send_header(k, v)
            except Exception:
                pass
        if not wrote_content_length:
            self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, status, html, extra_headers=None):
        body = html.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, location, set_cookies=None):
        self.send_response(302)
        self.send_header('Location', location)
        if set_cookies:
            for cookie_val in set_cookies:
                self.send_header('Set-Cookie', cookie_val)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def gateway_cookie_header(self, cookie_value):
        return (COOKIE_NAME + '=' + cookie_value +
                '; HttpOnly; SameSite=Lax; Max-Age=' + str(SESSION_HOURS * 3600) + '; Path=/')

    def handle_login_post(self):
        length   = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(length) if length > 0 else b''
        ct       = self.headers.get('Content-Type', '')

        if 'application/json' in ct:
            try:
                data     = json.loads(raw_body)
                username = data.get('username', '').strip()
                password = data.get('password', '').strip()
                is_json  = True
            except Exception:
                self.send_json(400, {'error': 'Invalid JSON'})
                return
        else:
            params   = parse_qs(raw_body.decode(errors='replace'))
            username = params.get('username', [''])[0].strip()
            password = params.get('password', [''])[0].strip()
            is_json  = False

        if not username or not password:
            if is_json:
                self.send_json(400, {'error': 'username and password required'})
            else:
                self.send_html(400, render_login('<div class="err">Please fill in both fields.</div>'))
            return

        status, resp_data = api_post('/api/v1/login', {'username': username, 'password': password})

        if status == 200:
            api_token = resp_data.get('token')
            if not api_token:
                if is_json:
                    self.send_json(502, {'error': 'No token from outpost'})
                else:
                    self.send_html(502, render_login('<div class="err">No token returned.</div>'))
                return
            gateway_cookie = make_session_cookie(username, api_token)
            logger.info('Session granted: %s', username)
            if is_json:
                body = json.dumps({'status': 'granted', 'user': username}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', len(body))
                self.send_header('Set-Cookie', self.gateway_cookie_header(gateway_cookie))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_redirect('/home', set_cookies=[self.gateway_cookie_header(gateway_cookie)])
        elif status == 401:
            if is_json:
                self.send_json(401, {'error': 'Invalid credentials'})
            else:
                self.send_html(401, render_login('<div class="err">Invalid username or password.</div>'))
        elif status == 403:
            if is_json:
                self.send_json(403, {'error': 'No active session on outpost'})
            else:
                self.send_html(403, render_login('<div class="err">No active session — log in locally first.</div>'))
        else:
            if is_json:
                self.send_json(502, {'error': 'Outpost error'})
            else:
                self.send_html(502, render_login('<div class="err">Could not reach outpost.</div>'))

    def do_GET(self):     self.route()
    def do_POST(self):    self.route()
    def do_PUT(self):     self.route()
    def do_DELETE(self):  self.route()
    def do_PATCH(self):   self.route()
    def do_OPTIONS(self): self.route()

    def route(self):
        parsed = urlparse(self.path)
        path   = parsed.path.lstrip('/')

        # ── Layer 1: Token gate verify endpoint ───────────────────────────────
        if path == 'verify':
            token        = self.headers.get('X-Outpost-Token', '').strip()
            claimed_user = self.headers.get('X-Outpost-User', '').strip()

            if not token:
                logger.warning('Gate: no token presented from %s', self.client_address[0])
                self.send_response(401)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            valid, username = verify_token(token)

            if not valid:
                logger.warning('Gate: invalid token from %s', self.client_address[0])
                self.send_response(401)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            logger.info('Gate: valid token for user %s', username)
            self.send_response(200)
            self.send_header('X-Outpost-User', username)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        # ── Gateway health ────────────────────────────────────────────────────
        if path == 'gateway/health':
            stored = load_token_hash()
            self.send_json(200, {
                'status':       'live',
                'service':      'auth-proxy',
                'gateway':      'samsung',
                'gate_armed':   stored is not None,
                'active_user':  stored.get('username') if stored else None
            })
            return

        if path == 'gateway/status':
            s = self.get_session()
            if s:
                self.send_json(200, {'authenticated': True, 'user': s.get('user')})
            else:
                self.send_json(401, {'authenticated': False})
            return

        if path == 'gateway/logout':
            self.send_response(302)
            self.send_header('Location', '/gateway/login')
            self.send_header('Set-Cookie', COOKIE_NAME + '=; HttpOnly; Max-Age=0; Path=/')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        if path == 'gateway/login':
            if self.command == 'POST':
                self.handle_login_post()
            else:
                self.send_html(200, render_login())
            return

        # ── Public paths — no session required ───────────────────────────────
        if any(path.startswith(p) for p in PUBLIC_PREFIXES):
            target = OUTPOST_UI + '/' + path
            if parsed.query:
                target += '?' + parsed.query
            status, headers_list, body = proxy_to(target, self)
            self.send_full_response(status, headers_list, body)
            return

        # ── All other routes — require session ────────────────────────────────
        session = self.get_session()

        if not session:
            if path.startswith('api/') or path == 'ws':
                self.send_json(401, {'error': 'Authentication required', 'login': '/gateway/login'})
            else:
                self.send_redirect('/gateway/login')
            return

        api_token = session.get('token')

        if path.startswith('api/') or path == 'ws':
            target = OUTPOST_API + '/' + path
        else:
            target = OUTPOST_UI + '/' + path
        if parsed.query:
            target += '?' + parsed.query

        status, headers_list, body = proxy_to(target, self, api_token=api_token)
        self.send_full_response(status, headers_list, body)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == '__main__':
    server = ThreadedHTTPServer(('0.0.0.0', PORT), AuthProxyHandler)
    logger.info('Auth proxy listening on port %d', PORT)
    logger.info('Outpost API: %s', OUTPOST_API)
    logger.info('Outpost UI:  %s', OUTPOST_UI)
    logger.info('Token gate:  %s', 'ARMED' if load_token_hash() else 'WAITING FOR KEY')
    server.serve_forever()
