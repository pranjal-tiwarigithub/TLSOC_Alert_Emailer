"""Fake Kibana + fake STARTTLS SMTP server for testing the alert emailer.

Both write what they received to JSON files so the test script can assert on it.
"""
from __future__ import annotations

import base64
import email
import json
import os
import re
import socket
import subprocess
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
QUERIES = os.path.join(HERE, "queries.json")
MAILBOX = os.path.join(HERE, "mailbox.json")
ALERTS = os.path.join(HERE, "alerts.json")

# Synthetic credentials for the fake servers. NEVER put a real credential here:
# this file is committed. The password shape matters, not its value - the
# trailing unpaired quote and the '&' are what exercise the .env parser.
USER = "fake_reader"
PASSWORD = 'nOt-A-r3al&pw?-?xy"'   # deliberately ends in an unpaired quote
SMTP_USER = "fake_smtp_user"
SMTP_PASSWORD = "00000000000000000000000000000000"


def ensure_cert():
    """Generate a throwaway self-signed cert for the fake SMTP server.

    Generated on demand and never committed: a private key in the repo is a
    private key in the repo, even a test one.
    """
    crt, key, pem = (os.path.join(HERE, n) for n in ("smtp.crt", "smtp.key", "smtp.pem"))
    if os.path.exists(pem) and os.path.exists(crt):
        return crt, pem
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
         "-days", "2", "-nodes", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )
    with open(pem, "wb") as out:
        for part in (key, crt):
            out.write(open(part, "rb").read())
    os.chmod(key, 0o600)
    os.chmod(pem, 0o600)
    return crt, pem


def append(path, item):
    data = json.load(open(path)) if os.path.exists(path) else []
    data.append(item)
    json.dump(data, open(path, "w"), indent=2, default=str)


# --------------------------------------------------------------------------
# Fake Kibana
# --------------------------------------------------------------------------

def matches(alert: dict, query: dict) -> bool:
    """Apply the script's own query the way Elasticsearch would."""
    filters = query["query"]["bool"]["filter"]
    rng = filters[0]["range"]["@timestamp"]
    gt = datetime.fromisoformat(rng["gt"].replace("Z", "+00:00"))
    lte = datetime.fromisoformat(rng["lte"].replace("Z", "+00:00"))
    ts = datetime.fromisoformat(alert["@timestamp"].replace("Z", "+00:00"))
    if not (gt < ts <= lte):
        return False
    shoulds = filters[1]["bool"]["should"]
    wanted = {v for clause in shoulds for v in list(clause["terms"].values())[0]}
    have = {alert.get("kibana.alert.rule.rule_id"), alert.get("kibana.alert.rule.uuid")}
    return bool(wanted & (have - {None}))


class KibanaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, pwd = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:
            return False
        return user == USER and pwd == PASSWORD

    def do_GET(self):
        if not self._authed():
            return self._json(401, {"error": "bad credentials"})
        if self.path == "/api/status":
            return self._json(200, {
                "version": {"number": "8.13.0"},
                "status": {"overall": {"level": "available"}},
            })
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._json(401, {"error": "bad credentials"})
        if self.path != "/api/detection_engine/signals/search":
            return self._json(404, {"error": f"no route {self.path}"})
        if self.headers.get("kbn-xsrf") is None:
            return self._json(400, {"error": "missing kbn-xsrf header"})

        length = int(self.headers.get("Content-Length", 0))
        query = json.loads(self.rfile.read(length))
        append(QUERIES, {"path": self.path, "query": query,
                         "xsrf": self.headers.get("kbn-xsrf")})

        alerts = json.load(open(ALERTS))
        hits = [
            {"_id": a["_id"], "_source": {k: v for k, v in a.items() if k != "_id"}}
            for a in alerts if matches(a, query)
        ]
        hits.sort(key=lambda h: h["_source"]["@timestamp"])
        hits = hits[: query["size"]]
        self._json(200, {"hits": {"total": {"value": len(hits)}, "hits": hits}})


def start_kibana(port: int):
    srv = ThreadingHTTPServer(("127.0.0.1", port), KibanaHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------
# Fake SMTP with STARTTLS + AUTH, which is what port 587 really does
# --------------------------------------------------------------------------

class SMTPSession(threading.Thread):
    def __init__(self, conn, ctx):
        super().__init__(daemon=True)
        self.conn, self.ctx = conn, ctx

    def run(self):
        try:
            self.handle()
        except Exception:
            pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def send(self, line):
        self.conn.sendall((line + "\r\n").encode())

    def readline(self, keep_indent=False):
        data = b""
        while not data.endswith(b"\r\n"):
            chunk = self.conn.recv(1)
            if not chunk:
                break
            data += chunk
        text = data.decode(errors="replace")
        # Leading whitespace is significant inside DATA: it is how RFC 5322
        # folds a long header across lines. Stripping it would silently turn
        # every header after a fold into message body.
        return text.rstrip("\r\n") if keep_indent else text.strip()

    def handle(self):
        self.send("220 fake.smtp ESMTP ready")
        authed = False
        envelope = {"from": None, "rcpt": []}
        while True:
            line = self.readline()
            if not line:
                return
            upper = line.upper()

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.send("250-fake.smtp")
                self.send("250-STARTTLS")
                self.send("250-AUTH PLAIN LOGIN")
                self.send("250 SIZE 10485760")
            elif upper == "STARTTLS":
                self.send("220 Ready to start TLS")
                self.conn = self.ctx.wrap_socket(self.conn, server_side=True)
            elif upper.startswith("AUTH PLAIN"):
                blob = line.split(None, 2)[2] if len(line.split()) > 2 else self.readline()
                _, user, pwd = base64.b64decode(blob).decode().split("\0")
                authed = (user == SMTP_USER and pwd == SMTP_PASSWORD)
                self.send("235 OK" if authed else "535 bad credentials")
            elif upper.startswith("AUTH LOGIN"):
                self.send("334 " + base64.b64encode(b"Username:").decode())
                user = base64.b64decode(self.readline()).decode()
                self.send("334 " + base64.b64encode(b"Password:").decode())
                pwd = base64.b64decode(self.readline()).decode()
                authed = (user == SMTP_USER and pwd == SMTP_PASSWORD)
                self.send("235 OK" if authed else "535 bad credentials")
            elif upper.startswith("MAIL FROM"):
                if not authed:
                    self.send("530 authentication required")
                    continue
                envelope = {"from": re.search(r"<(.*?)>", line).group(1), "rcpt": []}
                self.send("250 OK")
            elif upper.startswith("RCPT TO"):
                envelope["rcpt"].append(re.search(r"<(.*?)>", line).group(1))
                self.send("250 OK")
            elif upper == "DATA":
                self.send("354 End data with <CR><LF>.<CR><LF>")
                lines = []
                while True:
                    dl = self.readline(keep_indent=True)
                    if dl == ".":
                        break
                    if dl.startswith(".."):  # undo SMTP dot-stuffing
                        dl = dl[1:]
                    lines.append(dl)
                msg = email.message_from_string("\r\n".join(lines))
                append(MAILBOX, {
                    "envelope_from": envelope["from"],
                    "envelope_rcpt": envelope["rcpt"],
                    "headers": dict(msg.items()),
                    "body": msg.get_payload(),
                })
                self.send("250 OK queued")
            elif upper == "QUIT":
                self.send("221 Bye")
                return
            elif upper == "RSET":
                envelope = {"from": None, "rcpt": []}
                self.send("250 OK")
            else:
                self.send("250 OK")


def start_smtp(port: int, certfile: str):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)

    def loop():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            SMTPSession(conn, ctx).start()

    threading.Thread(target=loop, daemon=True).start()
    return sock


# --------------------------------------------------------------------------
# Alert fixtures
# --------------------------------------------------------------------------

def write_alerts():
    now = datetime.now(timezone.utc)

    def ago(minutes):
        return (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    alerts = [
        {   # in window, watched rule
            "_id": "alert-bruteforce-1",
            "@timestamp": ago(3),
            "kibana.alert.rule.rule_id": "brute-force-authentication",
            "kibana.alert.rule.uuid": "aaaaaaaa-0000-0000-0000-000000000001",
            "kibana.alert.rule.name": "Brute force authentication",
            "kibana.alert.severity": "high",
            "kibana.alert.risk_score": 73,
            "kibana.alert.reason": "10 failed logins for root on tlsoc-web-01",
            "host": {"name": "tlsoc-web-01"},
            "user": {"name": "root"},
            "source": {"ip": "203.0.113.9"},
        },
        {   # in window, watched by UUID only
            "_id": "alert-powershell-1",
            "@timestamp": ago(6),
            "kibana.alert.rule.rule_id": "suspicious-powershell",
            "kibana.alert.rule.uuid": "00000000-1111-2222-3333-444444444444",
            "kibana.alert.rule.name": "Suspicious PowerShell execution",
            "kibana.alert.severity": "critical",
            "kibana.alert.risk_score": 99,
            "host": {"name": "tlsoc-win-04"},
            "user": {"name": "svc_backup"},
            "process": {"name": "powershell.exe"},
        },
        {   # in window, rule NOT watched -> must never be emailed
            "_id": "alert-unwatched-1",
            "@timestamp": ago(2),
            "kibana.alert.rule.rule_id": "some-noisy-rule-we-ignore",
            "kibana.alert.rule.uuid": "cccccccc-0000-0000-0000-000000000003",
            "kibana.alert.rule.name": "Noisy rule nobody subscribed to",
            "kibana.alert.severity": "low",
            "host": {"name": "tlsoc-db-02"},
        },
        {   # watched rule but OUTSIDE the 10 minute window
            "_id": "alert-too-old-1",
            "@timestamp": ago(45),
            "kibana.alert.rule.rule_id": "brute-force-authentication",
            "kibana.alert.rule.uuid": "aaaaaaaa-0000-0000-0000-000000000004",
            "kibana.alert.rule.name": "Brute force authentication",
            "kibana.alert.severity": "high",
            "host": {"name": "tlsoc-web-09"},
        },
        {   # header-injection attempt in operator-visible fields
            "_id": "alert-injection-1",
            "@timestamp": ago(1),
            "kibana.alert.rule.rule_id": "brute-force-authentication",
            "kibana.alert.rule.uuid": "aaaaaaaa-0000-0000-0000-000000000005",
            "kibana.alert.rule.name": "Evil\r\nBcc: attacker@evil.example\r\nX-Injected: yes",
            "kibana.alert.severity": "high",
            "host": {"name": "tlsoc-\r\nweb-66"},
            "user": {"name": "attacker"},
        },
    ]
    json.dump(alerts, open(ALERTS, "w"), indent=2)
    return alerts
