"""Certificate pinning against a real local TLS server.

The server uses a self-signed certificate with a serial-number common name and
no Subject Alternative Name, the shape of a default FortiManager certificate.
"""
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

HAVE_OPENSSL = shutil.which("openssl") is not None

from fmg_client import FMGClient

LOGIN_OK = {"id": 1, "session": "S", "result": [{"status": {"code": 0, "message": "OK"},
                                                  "url": "/sys/login/user"}]}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps(LOGIN_OK).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def make_cert(directory: Path, cn: str):
    key, crt = directory / "k.pem", directory / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "2", "-subj", f"/CN={cn}"],
                   check=True, capture_output=True)
    der = ssl.PEM_cert_to_DER_cert(crt.read_text())
    return key, crt, hashlib.sha256(der).hexdigest()


@unittest.skipUnless(HAVE_OPENSSL, "needs the openssl command to make a test certificate")
class PinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        key, crt, cls.fp = make_cert(cls.dir, "FMG-VMTEST0000001")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.host = f"127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_correct_fingerprint_logs_in(self):
        with FMGClient(self.host, fingerprint=self.fp, timeout=5) as c:
            c.login("u", "p")

    def test_colon_separated_uppercase_fingerprint_is_accepted(self):
        fp = ":".join(self.fp[i:i + 2] for i in range(0, 64, 2)).upper()
        with FMGClient(self.host, fingerprint=fp, timeout=5) as c:
            c.login("u", "p")

    def test_wrong_fingerprint_is_refused(self):
        c = FMGClient(self.host, fingerprint="00" * 32, timeout=5)
        with self.assertRaises(requests.exceptions.SSLError):
            c.login("u", "p")

    def test_default_verification_refuses_a_self_signed_certificate(self):
        c = FMGClient(self.host, timeout=5)
        with self.assertRaises(requests.exceptions.SSLError):
            c.login("u", "p")

    def test_pin_is_not_overridden_by_requests_ca_bundle(self):
        # With REQUESTS_CA_BUNDLE set, requests ignores verify=False on a session.
        # The pin must still be the only check.
        old = os.environ.get("REQUESTS_CA_BUNDLE")
        os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
        try:
            with FMGClient(self.host, fingerprint=self.fp, timeout=5) as c:
                c.login("u", "p")
        finally:
            if old is None:
                os.environ.pop("REQUESTS_CA_BUNDLE")
            else:
                os.environ["REQUESTS_CA_BUNDLE"] = old

    def test_malformed_fingerprint_is_rejected_up_front(self):
        with self.assertRaises(ValueError):
            FMGClient(self.host, fingerprint="not-a-hash")


if __name__ == "__main__":
    unittest.main()
