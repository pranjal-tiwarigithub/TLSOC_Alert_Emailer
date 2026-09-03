#!/usr/bin/env bash
# Cron wrapper. flock guarantees two cycles can never overlap, which is what
# keeps the checkpoint and the sent-alert ledger consistent when a run is slow.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

exec flock -n .run.lock python3 tlsoc_alert_emailer.py run "$@"
