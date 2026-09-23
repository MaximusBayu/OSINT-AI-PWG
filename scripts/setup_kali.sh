#!/usr/bin/env bash
# Provision the OSINT collection host (Kali VPS) and smoke-test all five tools.
# ROADMAP Phase 0: "Provision Kali VPS; verify all 5 collection tools install and run a smoke target."
#
# Usage:
#   bash scripts/setup_kali.sh                 # install + version check
#   bash scripts/setup_kali.sh <probe_handle>  # also smoke-run tools against a THROWAWAY handle
#
# The probe handle MUST be a disposable/synthetic identity you control — never a real third party.
set -euo pipefail

PROBE="${1:-}"

echo "== 1/6 base packages =="
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv pipx git
pipx ensurepath || true

echo "== 2/6 theHarvester =="
sudo apt-get install -y theharvester || pipx install theHarvester

echo "== 3/6 Sherlock =="
pipx install sherlock-project || pipx install sherlock

echo "== 4/6 Holehe =="
pipx install holehe

echo "== 5/6 SpiderFoot =="
if [ ! -d "$HOME/spiderfoot" ]; then
  git clone https://github.com/smicallef/spiderfoot.git "$HOME/spiderfoot"
fi
python3 -m pip install --user -r "$HOME/spiderfoot/requirements.txt"

echo "== 6/6 version checks =="
theHarvester --version    || echo "WARN theHarvester check failed"
sherlock --version        || echo "WARN sherlock check failed"
holehe --help >/dev/null  && echo "holehe OK" || echo "WARN holehe check failed"
python3 "$HOME/spiderfoot/sf.py" -h >/dev/null && echo "spiderfoot OK" || echo "WARN spiderfoot check failed"
echo "NOTE: custom region scrapers (Tokopedia/Bukalapak) are built in Phase 2a; not installed here."

if [ -n "$PROBE" ]; then
  echo "== smoke run against throwaway handle: $PROBE =="
  echo "-- sherlock --"; sherlock "$PROBE" --timeout 10 --print-found || true
  echo "-- holehe --";   holehe "$PROBE@example.com" || true
  echo "-- theHarvester --"; theHarvester -d example.com -b bing -l 10 || true
  echo "(SpiderFoot smoke: launch web UI with: python3 ~/spiderfoot/sf.py -l 127.0.0.1:5001)"
fi

echo "DONE. Record tool versions in docs/ for reproducibility."
