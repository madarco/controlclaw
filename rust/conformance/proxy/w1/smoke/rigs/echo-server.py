"""Tiny HTTPS header-reflector for the smoke test. Replies with JSON describing the
request it received, so we can assert what the proxy actually forwarded upstream.

With ECHO_PEER_LOG set it also appends one line per ACCEPTED TCP connection, before any TLS
handshake. The residential-exit smoke needs that: the thing it has to prove is that the firewall
never opens a connection to the destination itself, and a connection that is opened and abandoned
never becomes a request."""
import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def _reflect(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        payload = {
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
        }
        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _reflect
    do_POST = _reflect
    do_PUT = _reflect
    do_DELETE = _reflect

    def log_message(self, *args):  # quiet
        pass


PEER_LOG = os.environ.get("ECHO_PEER_LOG", "")


class Server(ThreadingHTTPServer):
    """Records the peer at accept time and wraps TLS in the worker thread.

    Both halves matter. Wrapping the LISTENING socket would mean a connection that never
    handshakes is never seen, and "the firewall opened a connection and abandoned it" is exactly
    what the residential smoke has to detect. Wrapping in `get_request` instead would move the
    handshake onto the accept loop, where that same abandoned connection blocks every other
    client until it times out. So: peer here, handshake in `setup()`.
    """

    ssl_ctx: ssl.SSLContext | None = None

    def get_request(self):
        sock, addr = self.socket.accept()
        if PEER_LOG:
            try:
                with open(PEER_LOG, "a") as fh:
                    fh.write(f"{time.time():.3f} {addr[0]}\n")
            except OSError:
                pass
        sock.settimeout(30)
        return sock, addr


class TlsHandler(Handler):
    def setup(self):
        ctx = self.server.ssl_ctx  # type: ignore[attr-defined]
        if ctx is not None:
            self.request = ctx.wrap_socket(self.request, server_side=True)
            self.connection = self.request
        super().setup()


def serve(port: int, ctx: ssl.SSLContext | None) -> None:
    httpd = Server(("0.0.0.0", port), TlsHandler)
    httpd.ssl_ctx = ctx
    print(f"echo-server listening on :{port} ({'https' if ctx else 'http'})", flush=True)
    httpd.serve_forever()


def main():
    cert = os.environ.get("ECHO_CERT", "/certs/echo-cert.pem")
    key = os.environ.get("ECHO_KEY", "/certs/echo-key.pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    # A plaintext listener too, when asked for: the residential exit has a separate code path for
    # port 80 (no handshake to preserve) and it needs testing.
    plain = int(os.environ.get("ECHO_PLAIN_PORT", "0") or 0)
    if plain:
        threading.Thread(target=serve, args=(plain, None), daemon=True).start()
    serve(443, ctx)


if __name__ == "__main__":
    main()
