#!/usr/bin/env bash
# One-command server deploy for the CSMP free-nodes pipeline.
#
# What it does, in order:
#   1. checks git / docker / docker compose / flock are installed
#   2. pulls the latest code (skipped if this is not a git checkout)
#   3. builds the aggregate image and runs the pipeline once
#   4. starts the Caddy web service that serves the subscriptions
#   5. installs an every-6-hours cron job (idempotent, no duplicates)
#
# Before the first run, create free-nodes/.env from .env.example and set
# DOMAIN to the domain that points at this server (automatic HTTPS), or
# to http://SERVER_IP:8080 for a plain-HTTP test without a domain.
#
#   cp free-nodes/.env.example free-nodes/.env   # then edit DOMAIN
#   bash free-nodes/deploy-server.sh
#
# Subscription URLs after a successful run (DOMAIN=sub.example.com):
#   https://sub.example.com/clash.yaml
#   https://sub.example.com/v2ray.txt
#   https://sub.example.com/singbox.json
#   https://sub.example.com/report.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FN_DIR="$REPO_ROOT/free-nodes"
cd "$REPO_ROOT"

for cmd in git docker flock; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "docker compose plugin is missing" >&2; exit 1; }

if [ ! -f "$FN_DIR/.env" ]; then
  echo "free-nodes/.env is missing. Copy the example and set DOMAIN first:" >&2
  echo "  cp free-nodes/.env.example free-nodes/.env" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a; . "$FN_DIR/.env"; set +a
: "${DOMAIN:?DOMAIN is not set in free-nodes/.env}"
export PUID="${PUID:-$(id -u)}" PGID="${PGID:-$(id -g)}"
DOCKER="$(command -v docker)"
FLOCK="$(command -v flock)"
COMPOSE="$DOCKER compose -f free-nodes/compose.yaml --project-directory free-nodes"

mkdir -p free-nodes/data
chown -R "$PUID:$PGID" free-nodes/data || true

if [ -d .git ]; then
  echo "== pulling latest code =="
  git pull --ff-only
fi

echo "== building aggregate image =="
$COMPOSE build

echo "== running the pipeline once =="
$COMPOSE run --rm aggregate

echo "== starting the subscription web service =="
$COMPOSE up -d web

CRON_LINE="17 */6 * * * cd $REPO_ROOT && PUID=$PUID PGID=$PGID $FLOCK -n /tmp/csmp-free-nodes.lock $COMPOSE run --rm aggregate >> $HOME/csmp-free-nodes.log 2>&1"
if ! crontab -l 2>/dev/null | grep -Fq "csmp-free-nodes.lock"; then
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "== installed cron job (every 6 hours, minute 17) =="
else
  echo "== cron job already installed, leaving it alone =="
fi

BASE="$DOMAIN"
case "$BASE" in
  http://*|https://*) ;;
  *) BASE="https://$BASE" ;;
esac
echo
echo "Subscriptions (after the first successful run):"
echo "  $BASE/clash.yaml"
echo "  $BASE/v2ray.txt"
echo "  $BASE/singbox.json"
echo "  $BASE/report.json"
echo
echo "Health check: curl -s $BASE/healthz   (expect: ok)"
if ! curl --fail --silent --max-time 10 "$BASE/clash.yaml" >/dev/null; then
  echo "NOTE: $BASE/clash.yaml did not answer yet. If DOMAIN is new, check DNS points at this server and that ports 80/443 (or 8080 for http://) are open, then run: docker compose -f free-nodes/compose.yaml --project-directory free-nodes logs web"
fi
