#!/usr/bin/env python3
"""TLSOC Alert Emailer (MVP).

Polls the TLSOC stack for Elastic Security detection alerts raised in the
lookback window, keeps only the rule IDs listed in .env, and emails each one.
One invocation = one polling cycle, then exit. Run it from cron.

Everything - endpoints, credentials, rule IDs, recipients, window - comes from
.env. There is no second config file.

Standard library only: no pip install, nothing to break on a fresh server.

    python3 tlsoc_alert_emailer.py check          # .env + Kibana + rules + SMTP
    python3 tlsoc_alert_emailer.py test-email     # prove delivery works
    python3 tlsoc_alert_emailer.py run --dry-run  # format, send nothing
    python3 tlsoc_alert_emailer.py run
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import smtplib
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ENV = BASE_DIR / ".env"

# Deliberately strict: anything that is not a plain address is rejected rather
# than passed to the SMTP server.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

log = logging.getLogger("tlsoc_alert_emailer")


class ConfigError(Exception):
    """Configuration is unusable; the run cannot start."""


# --------------------------------------------------------------------------
# .env: the single source of configuration and the only home for secrets
# --------------------------------------------------------------------------

def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ without overriding real env vars."""
    if not path.exists():
        raise ConfigError(f"config file not found: {path} (copy .env.example)")

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ConfigError(
            f"{path} is readable by other users (mode {mode:04o}). "
            f"It holds passwords. Run: chmod 600 {path}"
        )

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, _, value = line.partition("=")
        key = key.strip()
        if not key.isidentifier():
            raise ConfigError(f"{path}:{lineno}: {key!r} is not a valid setting name")
        os.environ.setdefault(key, unquote_value(value))


def unquote_value(value: str) -> str:
    """Strip surrounding whitespace, and quotes only when they are a matched
    pair. Passwords legitimately contain a lone ' or " and must survive intact."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def env_str(name: str, default: str = "", aliases: tuple[str, ...] = ()) -> str:
    """First non-empty of name then aliases. Aliases exist so the .env can use
    whichever key name the operator already wrote."""
    for key in (name, *aliases):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return default


def env_required(name: str, aliases: tuple[str, ...] = ()) -> str:
    value = env_str(name, aliases=aliases)
    if not value:
        names = " (or ".join([name] + list(aliases)) + ")" * len(aliases)
        raise ConfigError(f"{names} is not set in .env")
    return value


def env_int(name: str, default: int) -> int:
    raw = env_str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None


def env_bool(name: str, default: bool) -> bool:
    raw = env_str(name).lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def env_list(name: str, aliases: tuple[str, ...] = ()) -> list[str]:
    """Comma- or whitespace-separated list, blanks dropped, order preserved."""
    raw = env_str(name, aliases=aliases)
    items = [part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()]
    return list(dict.fromkeys(items))  # de-duplicate, keep first occurrence


def env_emails(name: str, *, required: bool = False) -> list[str]:
    addresses = env_list(name)
    if required and not addresses:
        raise ConfigError(f"{name} is empty: nobody would be emailed")
    for addr in addresses:
        if not EMAIL_RE.match(addr):
            raise ConfigError(f"{name} contains an invalid email address: {addr!r}")
    return addresses


def build_url(explicit: str, host: str, port: str, scheme: str, default_port: str) -> str:
    """Accept either a full URL, or the host/IP + port pair written separately.

    Tolerates a full URL pasted into the host field, which is the likeliest
    way to get this wrong.
    """
    if explicit:
        base = explicit
    elif host:
        base = host
    else:
        return ""

    base = base.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = f"{scheme}://{base}"

    parsed = urllib.parse.urlsplit(base)
    if not parsed.hostname:
        raise ConfigError(f"cannot work out a hostname from {base!r}")
    if parsed.port is None:
        chosen = port or default_port
        if not chosen.isdigit():
            raise ConfigError(f"port must be numeric, got {chosen!r}")
        base = f"{parsed.scheme}://{parsed.hostname}:{chosen}"
    return base.rstrip("/")


def resolve_path(value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else (BASE_DIR / p)


def parse_rule_routes(raw: str) -> dict[str, list[str]]:
    """Optional per-rule extra recipients: 'rule-a:x@y.z|q@y.z; rule-b:w@y.z'."""
    routes: dict[str, list[str]] = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        rule_id, sep, addresses = chunk.partition(":")
        if not sep:
            raise ConfigError(
                f"RULE_ROUTES entry {chunk!r} is missing ':' "
                "(expected 'rule-id:person@example.org|other@example.org')"
            )
        parsed = [a.strip() for a in re.split(r"[|,]", addresses) if a.strip()]
        if not parsed:
            raise ConfigError(f"RULE_ROUTES entry for {rule_id.strip()!r} lists no address")
        for addr in parsed:
            if not EMAIL_RE.match(addr):
                raise ConfigError(f"RULE_ROUTES: invalid email address {addr!r}")
        routes[rule_id.strip()] = parsed
    return routes


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

class Settings:
    """Everything the run needs, validated up front so cron fails loudly."""

    def __init__(self) -> None:
        # --- where the alerts come from ------------------------------------
        scheme = env_str("ELK_SCHEME", "https")
        elk_host = env_str("ELK_IP_address", aliases=("ELK_IP_ADDRESS", "ELK_IP", "ELK_HOST"))
        self.kibana_url = build_url(
            env_str("KIBANA_URL"), elk_host, env_str("ELK_PORT"), scheme, "5601"
        )
        self.es_url = build_url(
            env_str("ES_URL"), env_str("ES_HOST"), env_str("ES_PORT"), scheme, "9200"
        )
        if not self.kibana_url and not self.es_url:
            raise ConfigError(
                "no endpoint configured: set ELK_IP_address (+ ELK_PORT), or KIBANA_URL, or ES_URL"
            )
        for label, url in (("KIBANA_URL", self.kibana_url), ("ES_URL", self.es_url)):
            if url and not url.startswith(("http://", "https://")):
                raise ConfigError(f"{label} must start with https:// (got {url!r})")
            if url.startswith("http://"):
                log.warning("%s is plain HTTP - credentials cross the network unencrypted", label)

        # Direct Elasticsearch wins when configured: a read-only ES account
        # cannot use the Kibana API, so this is the fallback that always works.
        self.use_es = bool(self.es_url)
        # Alerts are per-space. The default space is usually empty on a real
        # deploy, so getting this wrong looks exactly like "no alerts".
        self.kibana_space = env_str("KIBANA_SPACE", "default")
        if "/" in self.kibana_space:
            raise ConfigError(f"KIBANA_SPACE must be a space id, not a path: {self.kibana_space!r}")
        self.alert_index = env_str(
            "ALERT_INDEX", f".alerts-security.alerts-{self.kibana_space}"
        )
        self.username = env_required("ES_USERNAME")
        self.password = env_required("ES_PASSWORD")
        self.request_timeout = env_int("REQUEST_TIMEOUT", 30)
        self.tls_verify = env_bool("TLS_VERIFY", True)
        self.tls_ca_cert = env_str("TLS_CA_CERT")

        # --- which rules to alert on ---------------------------------------
        self.rule_ids = env_list("RULE_IDS")
        if not self.rule_ids:
            raise ConfigError("RULE_IDS is empty: there are no rules to alert on")

        # --- email ----------------------------------------------------------
        self.smtp_host = env_required("SMTP_HOST")
        self.smtp_port = env_int("SMTP_PORT", 587)
        self.smtp_tls_mode = env_str("SMTP_TLS_MODE", "starttls").lower()
        if self.smtp_tls_mode not in ("starttls", "ssl"):
            raise ConfigError(
                "SMTP_TLS_MODE must be 'starttls' or 'ssl' - plaintext SMTP is not allowed"
            )
        # Not validated as an email: plenty of relays authenticate a bare
        # username (an employee number, say).
        self.smtp_username = env_required("SMTP_USER", aliases=("SMTP_USERNAME",))
        self.smtp_password = env_required("SMTP_PASSWORD")
        self.smtp_ca_cert = env_str("SMTP_CA_CERT")
        self.smtp_timeout = env_int("SMTP_TIMEOUT", 30)

        self.email_from = env_str("EMAIL_FROM") or self.smtp_username
        if not EMAIL_RE.match(self.email_from):
            raise ConfigError(
                f"EMAIL_FROM is not a valid address: {self.email_from!r} "
                "(set EMAIL_FROM - SMTP_USER is not itself an email address here)"
            )
        self.email_to = env_emails("EMAIL_TO", required=True)
        self.email_cc = env_emails("EMAIL_CC")
        self.email_bcc = env_emails("EMAIL_BCC")
        self.rule_routes = parse_rule_routes(env_str("RULE_ROUTES"))
        unknown = [r for r in self.rule_routes if r not in self.rule_ids]
        if unknown:
            raise ConfigError(
                f"RULE_ROUTES mentions rule(s) missing from RULE_IDS: {', '.join(unknown)}"
            )
        self.subject_template = env_str(
            "EMAIL_SUBJECT_TEMPLATE", "[TLSOC][{severity}] {rule_name} on {host_or_ip}"
        )

        # --- window ---------------------------------------------------------
        self.lookback_minutes = env_int("LOOKBACK_MINUTES", 10)
        if self.lookback_minutes < 1:
            raise ConfigError("LOOKBACK_MINUTES must be at least 1")
        self.overlap_seconds = env_int("OVERLAP_SECONDS", 30)
        self.max_catchup_hours = env_int("MAX_CATCHUP_HOURS", 24)
        self.max_alerts_per_run = env_int("MAX_ALERTS_PER_RUN", 200)
        if self.max_alerts_per_run < 1:
            raise ConfigError("MAX_ALERTS_PER_RUN must be at least 1")
        self.use_checkpoint = env_bool("USE_CHECKPOINT", True)

        # --- files ----------------------------------------------------------
        self.state_file = resolve_path(env_str("STATE_FILE", "state/state.json"))
        self.log_file = env_str("LOG_FILE", "logs/alert_emailer.log")
        self.log_level = env_str("LOG_LEVEL", "INFO").upper()

    def recipients_for(self, rule_id: str | None) -> list[str]:
        extra = self.rule_routes.get(rule_id or "", [])
        return list(dict.fromkeys(self.email_to + extra))

    @property
    def kibana_link(self) -> str:
        return self.kibana_url or ""


# --------------------------------------------------------------------------
# State: checkpoint + ledger of alert IDs already emailed
# --------------------------------------------------------------------------

MAX_LEDGER = 5000


def fresh_state() -> dict:
    # checkpoint_kind: "clock" means the checkpoint is a wall-clock instant and
    # the next window re-scans OVERLAP_SECONDS behind it to catch late-indexed
    # alerts. "cursor" means it is the @timestamp of an alert already handled,
    # so the next window resumes strictly after it with no overlap - re-scanning
    # there would just re-read alerts we have already processed.
    return {"checkpoint": None, "checkpoint_kind": "clock", "sent_ids": []}


def load_state(path: Path) -> dict:
    if not path.exists():
        return fresh_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("state file %s is corrupt; starting from a fresh checkpoint", path)
        return fresh_state()
    if not isinstance(state, dict):
        log.warning("state file %s is not an object; starting fresh", path)
        return fresh_state()
    state.setdefault("checkpoint", None)
    if state.get("checkpoint_kind") not in ("clock", "cursor"):
        state["checkpoint_kind"] = "clock"
    if not isinstance(state.get("sent_ids"), list):
        state["sent_ids"] = []
    return state


def save_state(path: Path, state: dict) -> None:
    state["sent_ids"] = state["sent_ids"][-MAX_LEDGER:]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)  # atomic: a crash mid-write cannot lose the checkpoint


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Alert source: Kibana detection engine API, or Elasticsearch directly
# --------------------------------------------------------------------------

class AlertSource:
    """Reads detection alerts over HTTPS with basic auth.

    Two transports, one query. Kibana's detection-engine search endpoint is the
    default because it is the port most TLSOC deploys expose; ES_URL switches to
    Elasticsearch's _search, which is what a pure read-only ES role can reach.
    """

    def __init__(self, s: Settings):
        self.settings = s
        self.base = s.es_url if s.use_es else s.kibana_url
        self.timeout = s.request_timeout

        if s.tls_verify:
            if s.tls_ca_cert:
                ca_path = resolve_path(s.tls_ca_cert)
                if not ca_path.exists():
                    raise ConfigError(f"TLS_CA_CERT not found: {ca_path}")
                self.ssl_ctx = ssl.create_default_context(cafile=str(ca_path))
            else:
                # No private CA given: fall back to the system trust store.
                self.ssl_ctx = ssl.create_default_context()
        else:
            log.warning("TLS_VERIFY=false - certificate checks are OFF, use this only while testing")
            self.ssl_ctx = ssl._create_unverified_context()

        token = base64.b64encode(f"{s.username}:{s.password}".encode()).decode()
        self.auth_header = f"Basic {token}"

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self.auth_header)
        req.add_header("Content-Type", "application/json")
        req.add_header("kbn-xsrf", "tlsoc-alert-emailer")  # required by Kibana, ignored by ES
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            # `from None`: the traceback would carry the request object, and the
            # request carries the Authorization header.
            raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"cannot reach {self.base}: {exc.reason}") from None
        except json.JSONDecodeError:
            raise RuntimeError(f"{method} {path} returned a non-JSON response") from None

    def kbn(self, path: str) -> str:
        """Kibana API path for the configured space.

        The unprefixed path always means the *default* space, so on a stack
        whose alerts live in another space it silently returns nothing.
        """
        space = self.settings.kibana_space
        if space and space != "default":
            return f"/s/{urllib.parse.quote(space, safe='')}{path}"
        return path

    def ping(self) -> str:
        if self.settings.use_es:
            try:
                info = self._request("GET", "/")
                return f"Elasticsearch {info.get('version', {}).get('number', 'unknown')}"
            except RuntimeError as exc:
                # A properly least-privileged reader has no cluster:monitor, so
                # `GET /` is 403 while searching the alerts index works fine.
                # That is the account we want, not an error.
                if "HTTP 403" not in str(exc):
                    raise
                return "Elasticsearch (version hidden: account has no cluster monitor privilege)"
        info = self._request("GET", "/api/status")
        version = info.get("version", {}).get("number", "unknown")
        state = info.get("status", {}).get("overall", {}).get("level", "unknown")
        return f"Kibana {version} ({state})"

    def _query(self, rule_ids: list[str], start: datetime, end: datetime, size: int) -> dict:
        """Alerts with @timestamp in (start, end] matching any watched rule ID.

        Both rule_id (the stable, human-set identifier) and uuid (the generated
        one) are matched, so whichever the operator copied out of Kibana works.
        """
        return {
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gt": iso(start), "lte": iso(end)}}},
                        {
                            "bool": {
                                "minimum_should_match": 1,
                                "should": [
                                    {"terms": {"kibana.alert.rule.rule_id": rule_ids}},
                                    {"terms": {"kibana.alert.rule.uuid": rule_ids}},
                                ],
                            }
                        },
                    ]
                }
            },
        }

    def list_rules(self, limit: int) -> list[dict]:
        """Every detection rule the account can see, for filling in RULE_IDS."""
        if not self.settings.use_es:
            page = self._request(
                "GET", self.kbn(f"/api/detection_engine/rules/_find?per_page={limit}&page=1"
                                "&sort_field=name&sort_order=asc")
            )
            return [
                {
                    "rule_id": r.get("rule_id"),
                    "uuid": r.get("id"),
                    "name": r.get("name"),
                    "enabled": r.get("enabled"),
                    "severity": r.get("severity"),
                }
                for r in page.get("data", [])
            ]

        # No rules API on Elasticsearch: derive the list from alerts that exist.
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
            "aggs": {
                "rules": {
                    "terms": {"field": "kibana.alert.rule.rule_id", "size": limit},
                    "aggs": {"name": {"terms": {"field": "kibana.alert.rule.name", "size": 1}}},
                }
            },
        }
        index = urllib.parse.quote(self.settings.alert_index, safe=".*-_")
        result = self._request(
            "POST", f"/{index}/_search?ignore_unavailable=true&allow_no_indices=true", body
        )
        buckets = result.get("aggregations", {}).get("rules", {}).get("buckets", [])
        rules = []
        for bucket in buckets:
            names = bucket.get("name", {}).get("buckets", [])
            rules.append({
                "rule_id": bucket.get("key"),
                "uuid": None,
                "name": names[0]["key"] if names else "(unknown)",
                "enabled": None,
                "severity": None,
                "alerts_30d": bucket.get("doc_count"),
            })
        return rules

    def fetch_alerts(self, rule_ids: list[str], start: datetime, end: datetime, size: int) -> list[dict]:
        body = self._query(rule_ids, start, end, size)
        if self.settings.use_es:
            index = urllib.parse.quote(self.settings.alert_index, safe=".*-_")
            path = f"/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        else:
            path = self.kbn("/api/detection_engine/signals/search")
        result = self._request("POST", path, body)
        hits = result.get("hits", {}).get("hits", [])
        return hits if isinstance(hits, list) else []


# --------------------------------------------------------------------------
# Formatting - every value below is untrusted, attacker-influenced input
# --------------------------------------------------------------------------

def dig(source: dict, dotted: str):
    """Read a field that may be stored flat ('a.b') or nested ({'a':{'b':…}})."""
    if dotted in source:
        return source[dotted]
    node = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def as_text(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(as_text(v) for v in value) or "-"
    if isinstance(value, dict):
        return json.dumps(value, default=str)
    return str(value)


def one_line(value: str) -> str:
    """Collapse newlines. Anything reaching a mail header must be single-line,
    otherwise attacker-controlled alert text could inject extra headers."""
    return re.sub(r"[\r\n\t]+", " ", value).strip()


ALERT_FIELDS = [
    ("Rule", "kibana.alert.rule.name"),
    ("Rule ID", "kibana.alert.rule.rule_id"),
    ("Rule UUID", "kibana.alert.rule.uuid"),
    ("Severity", "kibana.alert.severity"),
    ("Risk score", "kibana.alert.risk_score"),
    ("Timestamp", "@timestamp"),
    ("Host", "host.name"),
    ("User", "user.name"),
    ("Source IP", "source.ip"),
    ("Destination IP", "destination.ip"),
    ("Process", "process.name"),
    ("Reason", "kibana.alert.reason"),
]

SUBJECT_TOKEN = re.compile(r"\{(\w+)\}")


def alert_rule_id(source: dict) -> str | None:
    for field in ("kibana.alert.rule.rule_id", "kibana.alert.rule.uuid"):
        rid = dig(source, field)
        if isinstance(rid, list):
            rid = rid[0] if rid else None
        if rid:
            return str(rid)
    return None


def format_subject(template: str, source: dict) -> str:
    values = {
        "rule_name": as_text(dig(source, "kibana.alert.rule.name")),
        "rule_id": as_text(dig(source, "kibana.alert.rule.rule_id")),
        "severity": as_text(dig(source, "kibana.alert.severity")),
        "risk_score": as_text(dig(source, "kibana.alert.risk_score")),
        "host": as_text(dig(source, "host.name")),
        "user": as_text(dig(source, "user.name")),
        "timestamp": as_text(dig(source, "@timestamp")),
        # Network-only alerts carry no host.name; the source IP is the useful
        # identifier there, and "on -" in a subject line tells you nothing.
        "host_or_ip": as_text(
            dig(source, "host.name") or dig(source, "source.ip") or "unknown"
        ),
    }
    # Deliberately not str.format: token substitution only, so no attribute or
    # index access is reachable from the template.
    subject = SUBJECT_TOKEN.sub(lambda m: values.get(m.group(1), m.group(0)), template)
    return one_line(subject)[:200] or "[TLSOC] detection alert"


def format_body(alert_id: str, source: dict, kibana_url: str) -> str:
    lines = ["A TLSOC detection rule you subscribe to has fired.", ""]
    for label, field in ALERT_FIELDS:
        value = dig(source, field)
        if value is not None:
            lines.append(f"{label:>15}: {as_text(value)}")
    lines += ["", f"{'Alert ID':>15}: {alert_id}"]
    if kibana_url:
        lines.append(f"{'Kibana':>15}: {kibana_url}/app/security/alerts")
    lines += [
        "",
        "-" * 60,
        "Sent by TLSOC Alert Emailer. Do not reply to this message.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------

class Mailer:
    def __init__(self, s: Settings):
        self.host = s.smtp_host
        self.port = s.smtp_port
        self.tls_mode = s.smtp_tls_mode
        self.username = s.smtp_username
        self.password = s.smtp_password
        self.from_address = s.email_from
        self.cc = s.email_cc
        self.bcc = s.email_bcc
        self.timeout = s.smtp_timeout
        if s.smtp_ca_cert:
            ca_path = resolve_path(s.smtp_ca_cert)
            if not ca_path.exists():
                raise ConfigError(f"SMTP_CA_CERT not found: {ca_path}")
            self.ssl_ctx = ssl.create_default_context(cafile=str(ca_path))
        else:
            self.ssl_ctx = ssl.create_default_context()

    def connect(self):
        if self.tls_mode == "ssl":
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=self.ssl_ctx)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.ehlo()
            server.starttls(context=self.ssl_ctx)
            server.ehlo()
        server.login(self.username, self.password)
        return server

    def send(self, recipients: list[str], subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.from_address
        msg["To"] = ", ".join(recipients)
        if self.cc:
            msg["Cc"] = ", ".join(self.cc)
        if self.bcc:
            # send_message() adds these to the envelope and strips the header,
            # so blind recipients stay blind.
            msg["Bcc"] = ", ".join(self.bcc)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid()
        msg["Auto-Submitted"] = "auto-generated"  # keeps out-of-office loops away
        msg.set_content(body)  # plain text only: nothing here is ever rendered as HTML
        with self.connect() as server:
            server.send_message(msg)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def setup_logging(s: Settings) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if s.log_file:
        path = resolve_path(s.log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    logging.basicConfig(
        level=getattr(logging, s.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=handlers,
        force=True,
    )


def cmd_check(s: Settings) -> int:
    log.info("config: OK (%d rule id(s) watched, %d base recipient(s))",
             len(s.rule_ids), len(s.email_to))
    log.info("lookback: %d minute(s), checkpoint %s",
             s.lookback_minutes, "enabled" if s.use_checkpoint else "disabled")

    source = AlertSource(s)
    log.info("alert source: OK - %s at %s%s", source.ping(), source.base,
             "" if s.tls_verify else " (TLS UNVERIFIED)")

    try:
        hits = source.fetch_alerts(s.rule_ids, utcnow() - timedelta(days=7), utcnow(), 1)
    except RuntimeError as exc:
        if "HTTP 403" in str(exc) and not s.use_es:
            raise ConfigError(
                "Kibana refused the alert search for this account (403). A read-only "
                "Elasticsearch role has no Kibana privileges - set ES_URL in .env to "
                "query Elasticsearch directly (usually port 9200)."
            ) from None
        raise

    if hits:
        log.info("rule ids: OK - matched an alert in the last 7 days")
    else:
        log.warning(
            "rule ids: readable, but NO alert matched RULE_IDS in the last 7 days. "
            "That is usually a typo - check them against Kibana > Security > Rules."
        )

    mailer = Mailer(s)
    with mailer.connect():
        log.info("smtp: OK - authenticated to %s:%d over %s",
                 mailer.host, mailer.port, mailer.tls_mode)
    return 0


def cmd_test_email(s: Settings) -> int:
    mailer = Mailer(s)
    mailer.send(
        s.email_to,
        "[TLSOC] Alert emailer test message",
        "This is a test from the TLSOC Alert Emailer.\n"
        "If you received it, delivery is working.\n"
        f"\nWatching {len(s.rule_ids)} rule id(s), {s.lookback_minutes}-minute lookback.\n",
    )
    log.info("test email sent to %s", ", ".join(s.email_to))
    return 0


def cmd_list_rules(s: Settings) -> int:
    """Print the rule IDs available in the stack, ready to paste into RULE_IDS."""
    source = AlertSource(s)
    rules = source.list_rules(limit=500)
    if not rules:
        log.warning("no detection rules visible to this account")
        return 0

    watched = set(s.rule_ids)
    log.info("%d rule(s) visible ('*' = already in RULE_IDS):", len(rules))
    for r in sorted(rules, key=lambda x: (not x.get("enabled", True), str(x.get("name")))):
        mark = "*" if (r["rule_id"] in watched or r["uuid"] in watched) else " "
        state = "" if r.get("enabled") is None else ("" if r["enabled"] else " [disabled]")
        counted = f" [{r['alerts_30d']} alerts/30d]" if r.get("alerts_30d") is not None else ""
        log.info("  %s %-45s %s%s%s", mark, r["rule_id"], r["name"], state, counted)

    missing = [r for r in watched if not any(
        r == x["rule_id"] or r == x["uuid"] for x in rules)]
    if missing:
        log.warning("in RULE_IDS but not found in the stack: %s", ", ".join(missing))
    return 0


def cmd_show_config(s: Settings) -> int:
    """Print the effective configuration. Never prints a secret."""
    rows = [
        ("alert source", "Elasticsearch (direct)" if s.use_es else "Kibana detection engine API"),
        ("endpoint", s.es_url if s.use_es else s.kibana_url),
        ("kibana space", s.kibana_space + (" (not used in ES mode)" if s.use_es else "")),
        ("index", s.alert_index if s.use_es else "(via Kibana API)"),
        ("es user", s.username),
        ("es password", f"set ({len(s.password)} chars)"),
        ("tls verify", str(s.tls_verify)),
        ("tls ca cert", s.tls_ca_cert or "(system trust store)"),
        ("rule ids", ", ".join(s.rule_ids)),
        ("to", ", ".join(s.email_to)),
        ("cc", ", ".join(s.email_cc) or "(none)"),
        ("bcc", ", ".join(s.email_bcc) or "(none)"),
        ("rule routes", "; ".join(f"{k} -> {', '.join(v)}" for k, v in s.rule_routes.items()) or "(none)"),
        ("smtp", f"{s.smtp_host}:{s.smtp_port} ({s.smtp_tls_mode})"),
        ("smtp user", s.smtp_username),
        ("smtp password", f"set ({len(s.smtp_password)} chars)"),
        ("from", s.email_from),
        ("subject", s.subject_template),
        ("lookback", f"{s.lookback_minutes} minute(s)"),
        ("overlap", f"{s.overlap_seconds} second(s)"),
        ("checkpoint", "enabled" if s.use_checkpoint else "disabled (fixed lookback window)"),
        ("max per run", str(s.max_alerts_per_run)),
        ("state file", str(s.state_file)),
    ]
    for key, value in rows:
        log.info("%-14s %s", key + ":", value)
    return 0


def window_start(s: Settings, state: dict, now: datetime) -> datetime:
    """Where this cycle begins. The checkpoint is what makes a late, skipped, or
    slow run lossless; LOOKBACK_MINUTES is the first window and the fallback."""
    if not s.use_checkpoint:
        return now - timedelta(minutes=s.lookback_minutes)

    checkpoint = state.get("checkpoint")
    if not checkpoint:
        start = now - timedelta(minutes=s.lookback_minutes)
        log.info("no checkpoint yet; first window looks back %d minute(s)", s.lookback_minutes)
        return start

    try:
        start = parse_iso(checkpoint)
    except ValueError:
        log.warning("checkpoint %r is unreadable; falling back to the lookback window", checkpoint)
        return now - timedelta(minutes=s.lookback_minutes)

    if state.get("checkpoint_kind") != "cursor":
        # Only a wall-clock checkpoint needs the overlap. Applying it to a
        # cursor would re-read the alert the cursor points at, and when
        # MAX_ALERTS_PER_RUN is small that re-read can fill the whole page and
        # wedge the checkpoint forever.
        start -= timedelta(seconds=s.overlap_seconds)

    floor = now - timedelta(hours=s.max_catchup_hours)
    if start < floor:
        log.warning("checkpoint older than MAX_CATCHUP_HOURS; skipping ahead to %s", iso(floor))
        return floor
    if start > now:
        log.warning("checkpoint is in the future (clock skew?); using the lookback window")
        return now - timedelta(minutes=s.lookback_minutes)
    return start


def advance_checkpoint(state: dict, s: Settings, now: datetime,
                       truncated: bool, cursor_ts: str | None) -> None:
    """Move the checkpoint to the end of what this cycle actually covered.

    Normally that is `now`. After truncation it must be the last alert handled,
    because the alerts that did not fit are still waiting behind it.
    """
    if not s.use_checkpoint:
        return
    if truncated and cursor_ts:
        state["checkpoint"] = cursor_ts
        state["checkpoint_kind"] = "cursor"
    else:
        state["checkpoint"] = iso(now)
        state["checkpoint_kind"] = "clock"


def alert_timestamp(hit: dict) -> str | None:
    value = dig(hit.get("_source", {}) or {}, "@timestamp")
    if value is None:
        return None
    text = as_text(value)
    try:
        parse_iso(text)
    except ValueError:
        return None
    return text


def cmd_run(s: Settings, dry_run: bool) -> int:
    state = load_state(s.state_file)
    now = utcnow()
    start = window_start(s, state, now)

    source = AlertSource(s)
    hits = source.fetch_alerts(s.rule_ids, start, now, s.max_alerts_per_run)
    log.info("window %s .. %s: %d alert(s) matched", iso(start), iso(now), len(hits))

    truncated = len(hits) >= s.max_alerts_per_run
    if truncated:
        log.warning(
            "hit MAX_ALERTS_PER_RUN (%d); the checkpoint will stop at the last alert "
            "processed so the rest arrive next cycle", s.max_alerts_per_run
        )

    already = set(state["sent_ids"])
    pending = [h for h in hits if h.get("_id") not in already]
    if len(pending) != len(hits):
        log.info("%d alert(s) already emailed on a previous run, skipped",
                 len(hits) - len(pending))

    # Everything fetched was handled, whether it was emailed now or on an
    # earlier cycle, so the checkpoint may pass all of it.
    fetched_cursor = alert_timestamp(hits[-1]) if hits else None

    if not pending:
        if not dry_run:
            advance_checkpoint(state, s, now, truncated, fetched_cursor)
            save_state(s.state_file, state)
        return 0

    mailer = None if dry_run else Mailer(s)
    sent = 0
    failed = False
    last_ts: str | None = None

    for hit in pending:
        alert = hit.get("_source", {}) or {}
        alert_id = str(hit.get("_id") or "unknown")
        rule_id = alert_rule_id(alert)
        recipients = s.recipients_for(rule_id)
        subject = format_subject(s.subject_template, alert)
        body = format_body(alert_id, alert, s.kibana_link)

        if dry_run:
            log.info("DRY RUN would email %r -> %s", subject, ", ".join(recipients))
            log.debug("DRY RUN body for %s:\n%s", alert_id, body)
            sent += 1
            continue

        try:
            mailer.send(recipients, subject, body)
        except Exception as exc:  # one bad send must not lose the other alerts
            log.error("failed to email alert %s: %s", alert_id, exc)
            failed = True
            break

        log.info("emailed alert %s (%s) to %d recipient(s)", alert_id, subject, len(recipients))
        state["sent_ids"].append(alert_id)
        last_ts = alert_timestamp(hit) or last_ts
        sent += 1

    if dry_run:
        log.info("DRY RUN complete: %d alert(s) would have been emailed; state unchanged", sent)
        return 0

    if failed:
        # Hold the checkpoint at the last successfully emailed alert so the next
        # run retries the rest. The ledger stops the sent ones repeating. With
        # nothing delivered the checkpoint stays put and the whole window is
        # retried.
        if s.use_checkpoint and last_ts:
            state["checkpoint"] = last_ts
            state["checkpoint_kind"] = "cursor"
        save_state(s.state_file, state)
        log.error("cycle ended early after a send failure; %d alert(s) delivered", sent)
        return 1

    advance_checkpoint(state, s, now, truncated, fetched_cursor)
    save_state(s.state_file, state)
    log.info("cycle complete: %d alert(s) emailed; checkpoint now %s",
             sent, state.get("checkpoint"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TLSOC Alert Emailer (MVP)")
    parser.add_argument("command",
                        choices=["run", "check", "test-email", "show-config", "list-rules"])
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV,
                        help="path to the .env holding all settings")
    parser.add_argument("--dry-run", action="store_true",
                        help="query and format, but send nothing and leave state untouched")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        load_env_file(args.env)
        settings = Settings()
        setup_logging(settings)
        if args.command == "check":
            return cmd_check(settings)
        if args.command == "test-email":
            return cmd_test_email(settings)
        if args.command == "show-config":
            return cmd_show_config(settings)
        if args.command == "list-rules":
            return cmd_list_rules(settings)
        return cmd_run(settings, args.dry_run)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 2
    except Exception as exc:
        log.error("run failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
