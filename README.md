# TLSOC Alert Emailer — MVP

Emails you Elastic Security detection alerts from your TLSOC stack, filtered to
a list of rule IDs you choose. One cron tick = one polling cycle = one exit.

Single file, **Python 3.9+ standard library only** — no `pip install`, nothing
to break on a fresh Ubuntu server. **All configuration lives in `.env`** —
endpoints, credentials, rule IDs, recipients, window. There is no second config
file.

```
cron every 10 min
   │
   ▼
run.sh ─── flock, so two cycles can never overlap
   │
   ▼
tlsoc_alert_emailer.py run
   │
   ├─ 1. work out the window ..... last 10 min, or from the saved checkpoint
   ├─ 2. query Kibana ............ alerts in that window whose rule is in RULE_IDS
   ├─ 3. drop already-sent ....... by alert _id, from the local ledger
   ├─ 4. email each alert ........ EMAIL_TO (+ RULE_ROUTES extras, + CC/BCC)
   └─ 5. advance the checkpoint ... only over what was actually handled
```

Together the checkpoint and the ledger mean a late, skipped, or manually
repeated run **never drops an alert and never sends a duplicate**.

---

## Deploy in 10 minutes

### 1. Create a read-only account

Do **not** put the `elastic` superuser in `.env`. In Kibana → Dev Tools:

```
POST _security/role/tlsoc_alert_reader
{
  "indices": [
    { "names": [".alerts-security.alerts-*"], "privileges": ["read", "view_index_metadata"] }
  ]
}

POST _security/user/tlsoc_alert_reader
{
  "password": "<generate a long random one>",
  "roles": ["tlsoc_alert_reader"],
  "full_name": "TLSOC Alert Emailer"
}
```

That account can read alerts and nothing else. If it leaks, no one can write,
delete, or reach any other index with it.

> **Kibana vs Elasticsearch.** By default the script reads alerts through
> Kibana's detection-engine API on `ELK_PORT` (5601). A *pure* Elasticsearch
> role like the one above has no Kibana privileges, so if `check` reports a
> **403**, either add the `securitySolution` read privilege to the account in
> Kibana → Stack Management → Roles, or set `ES_URL=https://<ip>:9200` in `.env`
> — the script then queries Elasticsearch directly with the same credentials.
> `check` tells you which of the two you need.

### 2. Configure

Everything is in one file:

```bash
chmod 600 .env          # the script refuses to run if this is group/world readable
$EDITOR .env
```

The settings that matter:

| Key | Notes |
|---|---|
| `ELK_IP_address`, `ELK_PORT` | Your Kibana. Use the **host IP**, not `localhost` — the server certificate lists the DNS name and the host IP, so `localhost` fails hostname verification. |
| `KIBANA_SPACE` | **The one that silently breaks everything.** Alerts are per-space and the default space is usually empty. The id is in your Kibana URL as `/s/<space-id>/`. |
| `RULE_IDS` | **The filter.** Comma-separated. Run `list-rules` to print what your stack actually has, or copy the `rule_id` / UUID from Kibana → Security → Rules → *rule* — both are matched. An alert whose rule is not listed is ignored. |
| `EMAIL_TO` | Everyone here gets every matched alert. `EMAIL_CC` / `EMAIL_BCC` optional. |
| `RULE_ROUTES` | Optional per-rule extra recipients, on top of `EMAIL_TO`. |
| `LOOKBACK_MINUTES` | How far back a run looks. **Match it to your cron interval.** |
| `TLS_VERIFY`, `TLS_CA_CERT` | Put your stack's CA at `certs/ca.crt` and set `TLS_CA_CERT=certs/ca.crt` to verify properly. See the note below. |
| `ES_URL` | Optional. Set it to bypass Kibana and query Elasticsearch directly. |

Check what the script actually parsed — secrets are masked:

```bash
python3 tlsoc_alert_emailer.py show-config
```

### 3. Turn TLS verification on

`.env` ships with `TLS_VERIFY=false` so your first run works before the
certificate is in place. **Fix this before you rely on it** — it logs a warning
every cycle until you do:

```bash
mkdir -p certs
cp /opt/TLSOCDockerDeploy/certs/ca/ca.crt certs/ca.crt
# then in .env:  TLS_VERIFY=true  and  TLS_CA_CERT=certs/ca.crt
```

Until then, credentials and alert data are encrypted but the server is
unauthenticated — anything on the path can impersonate your Kibana.

### 4. Verify, then go live

```bash
python3 tlsoc_alert_emailer.py show-config    # what did it actually read?
python3 tlsoc_alert_emailer.py list-rules     # rule IDs available, '*' = already watched
python3 tlsoc_alert_emailer.py check          # endpoint + rule IDs + SMTP login
python3 tlsoc_alert_emailer.py test-email     # proves delivery reaches the inbox
python3 tlsoc_alert_emailer.py run --dry-run  # shows the emails, sends nothing, state untouched
python3 tlsoc_alert_emailer.py run            # for real
```

`check` warns loudly if none of your rule IDs matched an alert in the last 7
days — that is almost always a typo'd rule ID, and it is the failure that would
otherwise look exactly like "quiet night".

### 5. Cron

```bash
chmod +x run.sh
crontab -e
```

```cron
*/10 * * * * /home/pranjaltiwari/Desktop/tlsoc-alert-emailer/run.sh >> /home/pranjaltiwari/Desktop/tlsoc-alert-emailer/logs/cron.log 2>&1
```

With `USE_CHECKPOINT=true` (the default) the window is driven by the checkpoint,
not the cron interval, so a late or skipped run still catches up. Set
`USE_CHECKPOINT=false` for a strict "last `LOOKBACK_MINUTES` minutes" window
every time.

---

## Tests

`tests/` starts a fake Kibana and a fake STARTTLS SMTP server, runs the real
script against them, and asserts on what was queried and what was delivered:

```bash
python3 tests/test_run.py       # 80 checks, no network, no real credentials
```

It covers rule-ID filtering, the time window, de-duplication, per-rule routing,
BCC blindness, the `MAX_ALERTS_PER_RUN` cap and catch-up, mail-header injection,
and every configuration failure mode. Run it after you change anything.

---

## Security in the MVP

These are in the code now — not deferred:

- **Everything in `.env`, mode-checked at startup** (0600 enforced), never
  logged, never on the command line where `ps` would show it. `show-config`
  prints the effective settings with secrets masked.
- **TLS on both hops.** Plaintext SMTP is refused outright; `TLS_VERIFY=false`
  is explicit and logs a warning every run. A private CA is supported on both
  hops (`TLS_CA_CERT`, `SMTP_CA_CERT`).
- **Least privilege** — a read-only ES account, documented above.
- **Header-injection safe** — alert text reaches the `Subject:` only after
  newlines are collapsed, so a rule name containing `\r\nBcc:` cannot add
  recipients. Tested.
- **Plain-text email only.** Alert bodies contain attacker-influenced strings
  (usernames, URLs, hostnames); nothing is rendered as HTML, so there is no
  injection surface in the mail client.
- **No template injection** — the subject template does token substitution, not
  `str.format`, so no attribute or index access is reachable from it.
- **Recipients validated** against a strict pattern at startup, not at send time.
- **Errors never leak credentials** — HTTP failures are re-raised with `from
  None` so the traceback cannot carry the `Authorization` header.
- **State file 0600, written atomically** — a crash mid-write cannot corrupt the
  checkpoint into replaying or skipping a day of alerts.
- **`flock`** so overlapping cycles cannot double-send.
- **Blast-radius cap** — `MAX_ALERTS_PER_RUN` (200) stops one noisy rule from
  emitting thousands of emails and getting your SMTP account throttled. The
  remainder is picked up next cycle, not dropped.

## Known MVP limits

Accepted deliberately to ship fast — each is a phase below:

- One email per alert (no digest/grouping). A noisy rule is loud; the cap stops
  it being catastrophic.
- Sends stop at the first SMTP failure; the cycle exits 1 and the next run
  retries the remainder. No retry/backoff within a cycle.
- The ledger keeps the last 5000 alert IDs. Above 5000 alerts per window the
  oldest could in theory re-send; raise `MAX_LEDGER` if you get near that.
- No alert enrichment, no per-rule throttling, no on-call schedules.
- Failure of the script itself is silent to you — nothing emails you when the
  emailer is down. That is Phase 1 below.

---

## From MVP to secure product

The order matters: each phase is shippable on its own, and each one is the
cheapest remaining risk reduction at that point.

**Phase 1 — Know it is alive (do this in week 1).**
A dead alert emailer is worse than none, because silence reads as "no alerts".
Write a heartbeat timestamp on every successful cycle and have a second, dumb
cron job email you if it goes stale for 30 minutes. Also alert on repeated
non-zero exits. This is ~30 lines and it is the single highest-value addition.

**Phase 2 — Get the secrets out of the file.**
`.env` at 0600 is a reasonable MVP, not an end state. Move to `systemd`
`LoadCredential=` with a timer instead of cron (also gives you journald logging,
`OnFailure=`, and a proper service identity), then to a real secret store
(Vault, or SOPS-encrypted files) once more than one person operates it. Rotate
the ES and SMTP credentials on a schedule and document how.

**Phase 3 — Grow the test suite with the code.**
`tests/` covers the logic that is hard to reproduce in production. Extend it as
you add features, and split the single file into `config` / `source` / `mail` /
`state` modules once it stops fitting in your head — the split is mechanical
now and expensive later.

**Phase 4 — Harden the runtime.**
Dedicated non-login system user, `systemd` sandboxing (`ProtectSystem=strict`,
`PrivateTmp=yes`, `NoNewPrivileges=yes`, `ReadWritePaths=` only the state and
log dirs), log rotation, and structured JSON logs so the emailer's own logs can
be ingested by TLSOC itself.

**Phase 5 — Supply chain and CI.**
Even with zero dependencies: pin the Python version, add `ruff` + `bandit` in
GitHub Actions, run `tests/test_run.py` on every push, sign your releases, and
add a `SECURITY.md`. Keep the zero-dependency property as long as you can — it
is the strongest supply-chain control you have.

**Phase 6 — Product features, safely.**
Digests and per-rule throttling, HTML email (only once you have a templating
layer that escapes by default), Slack/webhook sinks, a delivery audit trail, and
multi-tenant recipient routing. Add a per-recipient opt-out and PII review
before any alert content leaves your network — alert bodies contain usernames
and IPs, and once you email a customer they are in *their* mail archive forever.

**Cross-cutting, from now on:** treat every alert field as untrusted input, and
keep the "one cycle per invocation, then exit" design — it is why this thing is
safe to kill, restart, and reason about.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `certificate verify failed: hostname mismatch` | You used `localhost`. Use the host IP in `ELK_IP_address`. |
| `HTTP 403` from Kibana | The read-only ES account has no Kibana privileges. Set `ES_URL=https://<ip>:9200` in `.env`, or grant it `securitySolution` read. |
| `HTTP 401` | Wrong `ES_USERNAME` / `ES_PASSWORD`. If the password contains `#`, note that a `#` at the start of a line is a comment — mid-value it is fine. |
| `check` says no alerts matched in 7 days | Wrong `KIBANA_SPACE` (most likely) or a typo'd rule ID. Run `list-rules`. |
| `list-rules` prints nothing | The account cannot see rules in that space, or `KIBANA_SPACE` is wrong. In `ES_URL` mode it lists rules seen in the last 30 days of alerts instead. |
| `535 Username and Password not accepted` | Wrong SMTP credentials; for Gmail this must be an App Password. |
| Nothing arrives, no errors | The first run only looks back `LOOKBACK_MINUTES`. Delete `state/state.json` and raise it to backfill. |
| `.env is readable by other users` | `chmod 600 .env` |
