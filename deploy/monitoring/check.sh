#!/usr/bin/env bash
# Validate the monitoring configuration (#841).
#
#   deploy/monitoring/check.sh
#
# Runs promtool and amtool over the committed config and, critically, the alert
# RULE UNIT TESTS. `promtool check rules` only validates syntax: a rule can be
# syntactically perfect and still never fire — an expression that groups by a
# label which does not exist collapses every series into one group and
# evaluates to a constant. Two rules in alerts.yml were exactly that before the
# unit tests existed. An alert that cannot fire is worse than no alert, because
# it is believed.
#
# Exits non-zero on any failure. It fails CLOSED: a missing tool is an error,
# not a skip, because "the checks did not run" must never look like "the checks
# passed".
set -euo pipefail

cd "$(dirname "$0")"

PROM_IMAGE="${PROM_IMAGE:-prom/prometheus:v3.1.0}"
AM_IMAGE="${AM_IMAGE:-prom/alertmanager:v0.28.0}"

promtool_run() {
  if command -v promtool >/dev/null 2>&1; then
    promtool "$@"
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$PWD":/cfg -w /cfg --entrypoint promtool "$PROM_IMAGE" "$@"
  else
    echo "FAIL: neither promtool nor docker is available; cannot validate" >&2
    exit 1
  fi
}

amtool_run() {
  if command -v amtool >/dev/null 2>&1; then
    amtool "$@"
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$PWD":/cfg -w /cfg --entrypoint amtool "$AM_IMAGE" "$@"
  else
    echo "FAIL: neither amtool nor docker is available; cannot validate" >&2
    exit 1
  fi
}

echo "== prometheus config =="
promtool_run check config prometheus.yml

echo
echo "== alert rules: syntax =="
promtool_run check rules alerts.yml

echo
echo "== alert rules: unit tests (do they actually fire?) =="
promtool_run test rules alerts_test.yml

echo
echo "== alertmanager config =="
amtool_run check-config alertmanager.yml

echo
echo "== grafana dashboard: valid json =="
python3 -c 'import json,sys; d=json.load(open("grafana/dashboards/xe-node-health.json")); print("  panels:", len(d["panels"]))'

echo
echo "PASS: monitoring configuration is valid and the alert rules fire as specified"
