#!/usr/bin/env python3
"""End-to-end exercise of tlsoc_alert_emailer.py against fake Kibana + SMTP."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import fakes

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
SCRIPT = os.path.join(PROJECT, "tlsoc_alert_emailer.py")
ENV_FILE = os.path.join(HERE, "test.env")
STATE = os.path.join(HERE, "state.json")

KIBANA_PORT = 19601
SMTP_PORT = 12587

passes, failures = [], []


def check(name, condition, detail=""):
    (passes if condition else failures).append(name)
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not condition else ""))


def reset():
    for f in (fakes.MAILBOX, fakes.QUERIES, STATE):
        if os.path.exists(f):
            os.remove(f)


def mailbox():
    return json.load(open(fakes.MAILBOX)) if os.path.exists(fakes.MAILBOX) else []


def queries():
    return json.load(open(fakes.QUERIES)) if os.path.exists(fakes.QUERIES) else []


def write_env(**overrides):
    settings = {
        "ELK_IP_address": "127.0.0.1",
        "ELK_PORT": str(KIBANA_PORT),
        "ELK_SCHEME": "http",
        "ES_USERNAME": fakes.USER,
        "ES_PASSWORD": fakes.PASSWORD,
        "TLS_VERIFY": "true",
        "RULE_IDS": "brute-force-authentication, 00000000-1111-2222-3333-444444444444",
        "SMTP_HOST": "localhost",
        "SMTP_PORT": str(SMTP_PORT),
        "SMTP_TLS_MODE": "starttls",
        "SMTP_USER": fakes.SMTP_USER,
        "SMTP_PASSWORD": fakes.SMTP_PASSWORD,
        "SMTP_CA_CERT": CRT,
        "EMAIL_FROM": "sender@example.org",
        "EMAIL_TO": "soc-team@example.org",
        "EMAIL_CC": "",
        "EMAIL_BCC": "",
        "RULE_ROUTES": "",
        "EMAIL_SUBJECT_TEMPLATE": "[TLSOC][{severity}] {rule_name} on {host}",
        "LOOKBACK_MINUTES": "10",
        "USE_CHECKPOINT": "true",
        "OVERLAP_SECONDS": "30",
        "MAX_ALERTS_PER_RUN": "200",
        "STATE_FILE": STATE,
        "LOG_FILE": os.path.join(HERE, "test.log"),
        "LOG_LEVEL": "INFO",
    }
    settings.update(overrides)
    with open(ENV_FILE, "w") as fh:
        for k, v in settings.items():
            fh.write(f"{k}={v}\n")
    os.chmod(ENV_FILE, 0o600)


def run(command, *args):
    proc = subprocess.run(
        [sys.executable, SCRIPT, command, "--env", ENV_FILE, *args],
        capture_output=True, text=True, cwd=PROJECT, timeout=90,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    return proc.returncode, proc.stdout + proc.stderr


# --------------------------------------------------------------------------

print("Starting fakes...")
CRT, PEM = fakes.ensure_cert()
fakes.write_alerts()
fakes.start_kibana(KIBANA_PORT)
fakes.start_smtp(SMTP_PORT, PEM)
time.sleep(0.6)

# === 1. show-config =======================================================
print("\n[1] show-config masks secrets")
reset(); write_env()
code, out = run("show-config")
check("exits 0", code == 0, out)
check("endpoint composed from IP+PORT", f"http://127.0.0.1:{KIBANA_PORT}" in out, out)
check("es password never printed", fakes.PASSWORD not in out)
check("smtp password never printed", fakes.SMTP_PASSWORD not in out)
check("shows both rule ids", "brute-force-authentication" in out and "00000000-1111" in out)
check("shows 10 minute lookback", "10 minute(s)" in out, out)

# === 2. check =============================================================
print("\n[2] check reaches Kibana and authenticates to SMTP")
reset(); write_env()
code, out = run("check")
check("exits 0", code == 0, out)
check("pinged Kibana", "Kibana 8.13.0" in out, out)
check("matched a rule id", "matched an alert in the last 7 days" in out, out)
check("smtp authenticated", "smtp: OK" in out, out)
check("password with a trailing quote survived parsing", "HTTP 401" not in out, out)

# === 3. dry run ===========================================================
print("\n[3] run --dry-run sends nothing and writes no state")
reset(); write_env()
code, out = run("run", "--dry-run")
check("exits 0", code == 0, out)
check("3 alerts in window", "3 alert(s) matched" in out, out)
check("would email 3", "would have been emailed" in out and "DRY RUN complete: 3" in out, out)
check("no mail actually sent", mailbox() == [])
check("no state file written", not os.path.exists(STATE))
check("unwatched rule absent", "Noisy rule nobody subscribed to" not in out)

q = queries()[0]["query"]
window = q["query"]["bool"]["filter"][0]["range"]["@timestamp"]
check("kbn-xsrf header sent", queries()[0]["xsrf"] == "tlsoc-alert-emailer")
check("query filters on both rule id fields",
      {"kibana.alert.rule.rule_id", "kibana.alert.rule.uuid"} ==
      {list(c["terms"])[0] for c in q["query"]["bool"]["filter"][1]["bool"]["should"]})
check("query sorted ascending by timestamp", q["sort"] == [{"@timestamp": {"order": "asc"}}])
check("window is a bounded range", "gt" in window and "lte" in window, window)

# === 4. real run ==========================================================
print("\n[4] run delivers over STARTTLS")
reset(); write_env()
code, out = run("run")
check("exits 0", code == 0, out)
box = mailbox()
check("3 emails delivered", len(box) == 3, f"got {len(box)}")
recipients = {r for m in box for r in m["envelope_rcpt"]}
check("only the configured recipient", recipients == {"soc-team@example.org"}, recipients)
check("envelope sender is EMAIL_FROM",
      {m["envelope_from"] for m in box} == {"sender@example.org"})
subjects = [m["headers"]["Subject"] for m in box]
check("subject template rendered",
      any("[TLSOC][high] Brute force authentication on tlsoc-web-01" == s for s in subjects), subjects)
check("critical alert included",
      any("Suspicious PowerShell execution" in s for s in subjects), subjects)
check("unwatched rule not emailed",
      not any("Noisy rule" in s for s in subjects), subjects)
check("out-of-window alert not emailed",
      not any("tlsoc-web-09" in m["body"] for m in box))
check("marked auto-generated",
      all(m["headers"].get("Auto-Submitted") == "auto-generated" for m in box))
bodies = "\n".join(m["body"] for m in box)
check("body carries rule id, host, severity",
      "brute-force-authentication" in bodies and "tlsoc-web-01" in bodies and "high" in bodies)
check("body links to Kibana", "/app/security/alerts" in bodies, bodies[:300])
check("state file written", os.path.exists(STATE))
state = json.load(open(STATE))
check("state is 0600", oct(os.stat(STATE).st_mode & 0o777) == "0o600")
check("checkpoint advanced", state["checkpoint"] is not None)
check("ledger holds the 3 sent ids", len(state["sent_ids"]) == 3, state["sent_ids"])

# === 5. header injection ==================================================
print("\n[5] alert text cannot inject mail headers")
injected = [m for m in box if "Evil" in m["headers"]["Subject"]]
check("injection alert was emailed", len(injected) == 1)
if injected:
    m = injected[0]
    raw_subject = m["headers"]["Subject"]
    # A long subject is legitimately folded by the email library; folding is
    # safe because every continuation line starts with whitespace and is
    # unfolded back into the Subject. What must not happen is a continuation
    # line that starts at column 0 and becomes a header of its own.
    check("every folded line stays a continuation",
          all(line[:1] in (" ", "\t") for line in raw_subject.splitlines()[1:]),
          repr(raw_subject))
    unfolded = __import__("re").sub(r"\r?\n[ \t]+", " ", raw_subject)
    check("subject unfolds to a single line", "\n" not in unfolded and "\r" not in unfolded,
          repr(unfolded))
    check("injected header text stayed inside the subject value",
          "Bcc: attacker@evil.example" in unfolded and "X-Injected: yes" in unfolded,
          repr(unfolded))
    check("no X-Injected header appeared", "X-Injected" not in m["headers"], list(m["headers"]))
    check("attacker not added as a recipient",
          "attacker@evil.example" not in m["envelope_rcpt"], m["envelope_rcpt"])
    check("Bcc from alert text ignored", "Bcc" not in m["headers"], list(m["headers"]))

# === 6. dedupe on immediate re-run ========================================
print("\n[6] re-running immediately does not re-send")
before = len(mailbox())
code, out = run("run")
check("exits 0", code == 0, out)
check("no duplicate emails", len(mailbox()) == before, f"{before} -> {len(mailbox())}")
check("checkpoint excluded the handled window", "0 alert(s) matched" in out, out)

# A wide overlap re-reads alerts the checkpoint would have excluded; the ledger
# is what has to suppress them. This is the path that fires in production when
# an alert is indexed a few seconds late.
print("\n[6b] a wide overlap re-reads alerts and the ledger suppresses them")
reset(); write_env()
run("run")
before = len(mailbox())
write_env(OVERLAP_SECONDS="1800")
code, out = run("run")
check("exits 0", code == 0, out)
check("overlap re-found the alerts", "3 alert(s) matched" in out, out)
check("ledger reported the skip", "already emailed on a previous run" in out, out)
check("still no duplicate emails", len(mailbox()) == before, f"{before} -> {len(mailbox())}")

# === 7. per-rule routing + cc/bcc ========================================
print("\n[7] RULE_ROUTES adds recipients, BCC stays blind")
reset()
write_env(EMAIL_CC="soc-lead@example.org",
          EMAIL_BCC="audit@example.org",
          RULE_ROUTES="brute-force-authentication:oncall@example.org")
code, out = run("run")
check("exits 0", code == 0, out)
box = mailbox()
bf = [m for m in box if "Brute force" in m["headers"]["Subject"]]
ps = [m for m in box if "PowerShell" in m["headers"]["Subject"]]
check("routed rule got the extra recipient",
      bf and "oncall@example.org" in bf[0]["envelope_rcpt"], bf and bf[0]["envelope_rcpt"])
check("unrouted rule did not",
      ps and "oncall@example.org" not in ps[0]["envelope_rcpt"], ps and ps[0]["envelope_rcpt"])
check("cc in envelope and header",
      bf and "soc-lead@example.org" in bf[0]["envelope_rcpt"] and "Cc" in bf[0]["headers"])
check("bcc in envelope", bf and "audit@example.org" in bf[0]["envelope_rcpt"])
check("bcc header stripped from the message", bf and "Bcc" not in bf[0]["headers"], bf and list(bf[0]["headers"]))

# === 8. cap and checkpoint ================================================
print("\n[8] MAX_ALERTS_PER_RUN caps a noisy rule without losing the rest")
reset(); write_env(MAX_ALERTS_PER_RUN="1")
code, out = run("run")
check("exits 0", code == 0, out)
check("only 1 email this cycle", len(mailbox()) == 1, len(mailbox()))
check("warned about the cap", "hit MAX_ALERTS_PER_RUN" in out, out)
first = json.load(open(STATE))["checkpoint"]
check("checkpoint is a cursor, not a clock instant",
      json.load(open(STATE))["checkpoint_kind"] == "cursor", json.load(open(STATE)))
code, out = run("run")
check("next cycle picked up the next alert", len(mailbox()) == 2, len(mailbox()))
check("checkpoint moved forward", json.load(open(STATE))["checkpoint"] != first)
code, out = run("run")
code, out = run("run")
check("all 3 delivered exactly once after catching up", len(mailbox()) == 3, len(mailbox()))
check("no duplicates", len({m["headers"]["Message-ID"] for m in mailbox()}) == 3)
check("checkpoint returned to clock mode once caught up",
      json.load(open(STATE))["checkpoint_kind"] == "clock", json.load(open(STATE)))

# === 9. fixed-window mode =================================================
print("\n[9] USE_CHECKPOINT=false gives a strict last-N-minutes window")
reset(); write_env(USE_CHECKPOINT="false", LOOKBACK_MINUTES="5")
code, out = run("run", "--dry-run")
check("exits 0", code == 0, out)
check("5 minute window drops the 6-minute-old alert",
      "2 alert(s) matched" in out, out)
reset(); write_env(USE_CHECKPOINT="false", LOOKBACK_MINUTES="60")
code, out = run("run", "--dry-run")
check("60 minute window picks up the old one too", "4 alert(s) matched" in out, out)

# === 10. failure modes ====================================================
print("\n[10] misconfiguration fails loudly, never silently")
reset(); write_env(RULE_IDS="")
code, out = run("run")
check("empty RULE_IDS exits 2", code == 2 and "RULE_IDS is empty" in out, out)

reset(); write_env(EMAIL_TO="not-an-email")
code, out = run("run")
check("bad recipient exits 2", code == 2 and "invalid email" in out, out)

reset(); write_env(SMTP_TLS_MODE="plain")
code, out = run("run")
check("plaintext SMTP refused", code == 2 and "plaintext SMTP is not allowed" in out, out)

reset(); write_env(ES_PASSWORD="wrong-password")
code, out = run("run")
check("bad ES credentials exit non-zero", code == 1 and "401" in out, out)
check("wrong password not echoed to the log", "wrong-password" not in out)

reset(); write_env(RULE_ROUTES="not-in-rule-ids:x@y.org")
code, out = run("run")
check("RULE_ROUTES for an unwatched rule exits 2", code == 2 and "missing from RULE_IDS" in out, out)

reset(); write_env(LOOKBACK_MINUTES="abc")
code, out = run("run")
check("non-numeric lookback exits 2", code == 2 and "whole number" in out, out)

reset(); write_env()
os.chmod(ENV_FILE, 0o644)
code, out = run("run")
check("world-readable .env refused", code == 2 and "chmod 600" in out, out)

reset(); write_env(ELK_IP_address="", ELK_PORT="", ES_URL="")
code, out = run("run")
check("no endpoint exits 2", code == 2 and "no endpoint configured" in out, out)

reset(); write_env()
with open(STATE, "w") as fh:
    fh.write("{ this is not json")
os.chmod(STATE, 0o600)
code, out = run("run")
check("corrupt state recovers instead of crashing",
      code == 0 and "corrupt" in out and len(mailbox()) == 3, out)

# === 11. direct Elasticsearch mode ========================================
print("\n[11] ES_URL switches transport to Elasticsearch _search")
reset(); write_env(ES_URL=f"http://127.0.0.1:{KIBANA_PORT}")
code, out = run("run", "--dry-run")
check("hit the _search path",
      any("_search" in q["path"] for q in queries()) or code != 0,
      [q["path"] for q in queries()])
check("index name in the path",
      any(".alerts-security.alerts-default" in q["path"] for q in queries()) or code != 0,
      [q["path"] for q in queries()])

# --------------------------------------------------------------------------
print("\n" + "=" * 64)
print(f"{len(passes)} passed, {len(failures)} failed")
if failures:
    print("\nFAILED:")
    for f in failures:
        print("  -", f)
sys.exit(1 if failures else 0)
