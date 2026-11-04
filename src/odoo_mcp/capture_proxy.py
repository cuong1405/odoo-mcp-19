"""Local-only browser proxy: validate DNS and connect to the checked numeric IP.

Unlike route-only DNS checks, this pins the actual TCP peer and closes the
validation/use race. Every redirect and subrequest must use the same proxy.
"""

import select
import socket
import socketserver
import threading
from contextlib import contextmanager
from urllib.parse import urlsplit

from .capture_policy import CaptureError, CapturePolicy


def connect_checked(policy: CapturePolicy, url: str) -> socket.socket:
    host, port = policy.validate_url(url)
    addresses = policy.resolve(host, port)
    for family, kind, protocol, _, sockaddr in addresses:
        upstream = socket.socket(family, kind, protocol)
        upstream.settimeout(policy.navigation_timeout)
        try:
            upstream.connect(sockaddr)  # numeric address, never another hostname lookup
            return upstream
        except OSError:
            upstream.close()
    raise CaptureError("Capture destination connection failed")


class _Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, policy, credential_origin=None):
        self.policy = policy
        self.credential_origin = credential_origin
        self.blocked = False
        self.failure = None
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", 0), _Handler)

    def handle_error(self, request, client_address):
        pass  # Socket errors must not log request headers or credentials.


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        if not self.server.slots.acquire(blocking=False):
            return
        try:
            self._handle()
        finally:
            self.server.slots.release()

    def _handle(self):
        self.connection.settimeout(self.server.policy.timeout)
        upstream = None
        try:
            line = self.rfile.readline(8193)
            if len(line) > 8192:
                raise CaptureError("Proxy request limit exceeded")
            method, target, _ = line.decode("ascii").strip().split(" ", 2)
            headers = []
            size = 0
            while True:
                header = self.rfile.readline(8193)
                size += len(header)
                if not header or header == b"\r\n":
                    break
                if len(header) > 8192 or size > 65536:
                    raise CaptureError("Proxy header limit exceeded")
                headers.append(header)
            if method == "CONNECT":
                url = f"https://{target}"
            else:
                if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
                    raise CaptureError("Proxy method blocked")
                url = target
            if self.server.credential_origin is not None:
                parsed = urlsplit(url)
                destination = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                if destination != self.server.credential_origin:
                    raise CaptureError("Authenticated captures permit connections to the source origin only")
            upstream = connect_checked(self.server.policy, url)
            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
            else:
                parsed = urlsplit(url)
                path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
                upstream.sendall(f"{method} {path} HTTP/1.1\r\n".encode("ascii"))
                for header in headers:
                    key = header.split(b":", 1)[0].lower()
                    if key not in {b"host", b"connection", b"proxy-connection", b"proxy-authorization", b"upgrade"}:
                        upstream.sendall(header)
                upstream.sendall(f"Host: {parsed.netloc}\r\nConnection: close\r\n\r\n".encode("ascii"))
                content_length = 0
                for header in headers:
                    key, _, value = header.partition(b":")
                    if key.lower() == b"transfer-encoding":
                        raise CaptureError("Chunked proxy requests are unsupported")
                    if key.lower() == b"content-length":
                        content_length = int(value.strip())
                if not 0 <= content_length <= 1024 * 1024:
                    raise CaptureError("Proxy request body exceeds its limit")
                if content_length:
                    upstream.sendall(self.rfile.read(content_length))
            # CONNECT tunnels TLS unchanged; Chromium retains normal certificate validation.
            while True:
                readable, _, _ = select.select([self.connection, upstream], [], [], 1)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)
        except CaptureError as exc:
            self.server.blocked = True
            self.server.failure = str(exc)
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except (OSError, ValueError, UnicodeError):
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            if upstream is not None:
                upstream.close()


@contextmanager
def capture_proxy(policy: CapturePolicy, credential_origin=None):
    with _Proxy(policy, credential_origin) as proxy:
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            yield proxy
        finally:
            proxy.shutdown()
            thread.join(timeout=2)
