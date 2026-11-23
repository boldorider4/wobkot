import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CERT = HERE / 'cert.pem'
DEFAULT_KEY = HERE / 'key.pem'
DEFAULT_CN = 'manuals.playstation.net'
DEFAULT_SANS = ['manuals.playstation.net', 'manuals.playstation.sony.com', 'localhost']

# --- auto payload delivery -------------------------------------------------
# Optional override. When None, the console's address is taken from its /log POST.
PLDMGR_IP = None
PLDMGR_PORT = 9021
PLDMGR_ELF = Path.home('/path/to/pldmgr_v0.6.3.elf')
PLDMGR_DELAY = 5  # seconds to wait after elfldr starts
PLDMGR_TRIGGER = 'Created bin thread'  # PS5 log line that arms the timer

_pldmgr_armed = threading.Event()
_pldmgr_lock = threading.Lock()
_pldmgr_status = 'idle'
_pldmgr_error = None
_pldmgr_target = None


def set_pldmgr_target(ip):
    global _pldmgr_target

    if ip:
        _pldmgr_target = ip


def pldmgr_target():
    return PLDMGR_IP or _pldmgr_target


def set_pldmgr_status(status, error=None):
    global _pldmgr_status, _pldmgr_error

    with _pldmgr_lock:
        _pldmgr_status = status
        _pldmgr_error = error


def detect_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()


def ensure_cert(cert, key, ip):
    if cert.exists() and key.exists():
        return
    if not shutil.which('openssl'):
        raise SystemExit(f'[cert] missing {cert} / {key} and openssl is not on PATH')

    print(f'[cert] {cert} / {key} missing - generating self-signed cert for {DEFAULT_CN} ({ip}) ...')
    depends = ','.join(f'DNS:{name}' for name in DEFAULT_SANS) + f',IP:{ip}'
    base = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
        '-keyout', str(key), '-out', str(cert), '-subj', f'/CN={DEFAULT_CN}',
    ]
    result = subprocess.run(base + ['-addext', f'subjectAltName={depends}'],
                            capture_output=True, text=True)
    if result.returncode != 0:
        result = subprocess.run(base, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f'[cert] auto-generation failed:\n{result.stderr.strip()}')

    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    print(f'[cert] wrote {cert} and {key} (valid 10 years)')


def send_pldmgr():
    # Equivalent to: nc <console> PLDMGR_PORT < PLDMGR_ELF
    target = pldmgr_target()

    if not target:
        print('[pldmgr] no console address seen in /log - skipping send', flush=True)
        set_pldmgr_status('error', 'no console address seen in /log')
        return

    print(f'[pldmgr] sending {PLDMGR_ELF} -> {target}:{PLDMGR_PORT}', flush=True)
    set_pldmgr_status('sending')
    try:
        with PLDMGR_ELF.open('rb') as f, socket.create_connection(
            (target, PLDMGR_PORT), timeout=10
        ) as sock:
            while chunk := f.read(1 << 16):
                sock.sendall(chunk)
            sock.shutdown(socket.SHUT_WR)
        print(f'[pldmgr] sent {PLDMGR_ELF.stat().st_size} bytes', flush=True)
        set_pldmgr_status('sent')
    except OSError as e:
        print(f'[pldmgr] send failed: {e}', flush=True)
        set_pldmgr_status('error', str(e))


def arm_pldmgr():
    if _pldmgr_armed.is_set():
        return

    _pldmgr_armed.set()
    set_pldmgr_status('armed')
    print(f'[pldmgr] {pldmgr_target() or "console"} up - firing in {PLDMGR_DELAY}s', flush=True)

    timer = threading.Timer(PLDMGR_DELAY, send_pldmgr)
    timer.daemon = True
    timer.start()


class WobkotHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        '.bin': 'application/octet-stream',
        '.elf': 'application/octet-stream',
    }

    def do_GET(self):
        if self.path.split('?', 1)[0] != '/pldmgr':
            return super().do_GET()

        with _pldmgr_lock:
            payload = {
                'status': _pldmgr_status,
                'error': _pldmgr_error,
                'delay': PLDMGR_DELAY,
                'ip': pldmgr_target(),
                'port': PLDMGR_PORT,
                'file': str(PLDMGR_ELF),
            }

        body = json.dumps(payload).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_head(self):
        if os.path.exists(self.translate_path(self.path)):
            return super().send_head()

        self.send_response(302)
        self.send_header('Location', '/')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return None

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Pragma', 'no-cache')
        super().end_headers()

    def log_request(self, code='-', size='-'):
        ua = self.headers.get('User-Agent', '-') if self.headers else '-'
        self.log_message('"%s" %s %s UA="%s"', self.requestline, code, size, ua)

    def do_POST(self):
        if self.path != '/log':
            self.send_error(404)
            return

        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length).decode('utf-8', 'replace')

        # The browser that posts its logs is the console we send pldmgr to.
        set_pldmgr_target(self.client_address[0])

        for line in body.splitlines():
            print(f'[ps5] {line}', flush=True)
            if PLDMGR_TRIGGER in line:
                arm_pldmgr()

        self.send_response(204)
        self.send_header('Content-Length', '0')
        self.end_headers()


class RedirectHandler(BaseHTTPRequestHandler):
    default_host = '127.0.0.1'
    https_port = 443

    def do_GET(self):
        self._redirect()

    def do_HEAD(self):
        self._redirect()

    def _redirect(self):
        host = self.headers.get('Host') or self.default_host
        if host.startswith('['):
            host = host.split(']')[0] + ']'
        else:
            host = host.split(':')[0]
        port = '' if self.https_port == 443 else f':{self.https_port}'
        self.send_response(302)
        self.send_header('Location', f'https://{host}{port}{self.path}')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        self.end_headers()


def make_server(bind, port, handler, label, context=None):
    try:
        server = ThreadingHTTPServer((bind, port), handler)
    except OSError as e:
        if e.errno == 13:
            raise SystemExit(f'cannot bind {label} {port} - retry with: sudo {Path(__file__).name}')
        if e.errno == 48:
            raise SystemExit(f'{label}/{port} already in use')
        raise
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def parse_args():
    p = argparse.ArgumentParser(description='Serve this directory over HTTPS (with an HTTP-to-HTTPS redirect).')
    p.add_argument('--bind', default='0.0.0.0', help='address to bind (default: 0.0.0.0)')
    p.add_argument('--https-port', type=int, default=443, help='HTTPS port (default: 443, needs root)')
    p.add_argument('--http-port', type=int, default=80, help='HTTP port that redirects to HTTPS (default: 80)')
    p.add_argument('--no-http', action='store_true', help='disable the HTTP redirect listener')
    p.add_argument('--root', default=str(HERE), help=f'directory to serve (default: {HERE})')
    p.add_argument('--cert', help='TLS certificate chain (may include the key)')
    p.add_argument('--key', help='TLS private key (omit if the key is in --cert)')
    p.add_argument('--ip', help='address used in the generated certificate (default: auto-detect LAN IP)')
    args = p.parse_args()
    if args.key and not args.cert:
        p.error('--key requires --cert')
    return args


def main():
    args = parse_args()
    ip = args.ip or detect_ip()

    if args.cert:
        cert, key = Path(args.cert), Path(args.key) if args.key else None
        if not cert.exists() or (key is not None and not key.exists()):
            raise SystemExit(f'[cert] missing {cert} or {key}')
    else:
        cert, key = DEFAULT_CERT, DEFAULT_KEY
        ensure_cert(cert, key, ip)

    root = str(Path(args.root).resolve())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key) if key is not None else None)

    httpsd = make_server(args.bind, args.https_port, partial(WobkotHandler, directory=root),
                         'https', context)

    RedirectHandler.default_host = ip
    RedirectHandler.https_port = args.https_port
    httpd = None
    if not args.no_http and args.http_port:
        httpd = make_server(args.bind, args.http_port, RedirectHandler, 'http')
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    print(f'running server !! serving {root}')
    if httpd:
        print(f'[host] http://{ip}:{args.http_port} -> https://{ip}:{args.https_port}')
    print(f'[host] https://{ip}:{args.https_port}')
    print(f"[host] PS5 flow: Settings > Network > manual DNS {ip} -> User's Guide -> accept certificate warning")
    if PLDMGR_ELF.exists():
        target = PLDMGR_IP or 'console address from /log'
        print(f'[pldmgr] armed: {PLDMGR_ELF.name} -> {target}:{PLDMGR_PORT} ({PLDMGR_DELAY}s after elfldr)')
    else:
        print(f'[pldmgr] warning: {PLDMGR_ELF} not found - auto-send will fail')

    try:
        httpsd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if httpd:
            httpd.shutdown()


if __name__ == '__main__':
    main()
