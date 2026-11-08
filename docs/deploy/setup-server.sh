#!/usr/bin/env bash
# Custody Core: one-file server setup for a plain Ubuntu/Debian server with Docker (for example a DigitalOcean
# droplet from the "Docker on Ubuntu" image).
#
# Run it from inside a checkout of this repository, as root:
#   sudo bash docs/deploy/setup-server.sh            first install, and every update (it rebuilds and restarts)
#   sudo bash docs/deploy/setup-server.sh github     add the GitHub App settings later
#   sudo bash docs/deploy/setup-server.sh status     show what is running and the health check
#
# It asks for the few values it cannot know, makes the two secrets itself, builds the image, starts the app with a
# persistent volume for backup snapshots, and puts Caddy in front of it for automatic https.
# Settings live in /opt/custody/custody.env (readable by root only). Re-running keeps them, including
# MFA_ENCRYPTION_KEY, which is never regenerated: if it were lost or replaced, everyone would have to set up their
# authenticator app again.
set -euo pipefail

DIR=/opt/custody
ENV_FILE="$DIR/custody.env"
NET=custody
IMAGE=custody-core

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf '\nStopped: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root: sudo bash docs/deploy/setup-server.sh"
command -v docker >/dev/null || die "Docker is not installed. Use the 'Docker on Ubuntu' image, or install Docker first."

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -f "$REPO_DIR/Dockerfile" ] || die "run this from inside a checkout of the Custody Core repository (no Dockerfile found at $REPO_DIR)."

mkdir -p "$DIR"
chmod 700 "$DIR"

# Reads KEY from the settings file ('' if absent).
get() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | head -n1 | cut -d= -f2- || true; }

# Sets KEY=VALUE in the settings file (replacing any old line), keeping the file private.
put() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp "$DIR/.env.XXXXXX")"
  [ -f "$ENV_FILE" ] && grep -vE "^${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

ask() { # ask VAR "prompt" [secret]
  local var="$1" prompt="$2" secret="${3:-}" current answer
  current="$(get "$var")"
  if [ -n "$current" ]; then
    if [ -n "$secret" ]; then prompt="$prompt [Enter keeps the saved value]"; else prompt="$prompt [$current]"; fi
  fi
  while true; do
    if [ -n "$secret" ]; then read -r -s -p "$prompt: " answer; echo; else read -r -p "$prompt: " answer; fi
    answer="${answer:-$current}"
    [ -n "$answer" ] && break
    echo "  This one is required."
  done
  put "$var" "$answer"
}

container_running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]; }

health() {
  local domain; domain="$(get APP_URL | sed 's#^https\?://##')"
  echo "Containers:"; docker ps --filter name=custody-core --filter name=custody-caddy --format '  {{.Names}}  {{.Status}}'
  echo "Health check:"
  curl -fsS --max-time 10 "https://$domain/api/v1/health" || echo "  (no answer from https://$domain yet)"
  echo
}

# ---------------------------------------------------------------------------------------------------------------
if [ "${1:-}" = "status" ]; then health; exit 0; fi

if [ "${1:-}" = "github" ]; then
  [ -f "$ENV_FILE" ] || die "run the first install before adding GitHub settings."
  say "GitHub App settings (docs/GITHUB_APP_SETUP.md, steps 1 and 2)"
  ask GITHUB_APP_ID "App ID"
  ask GITHUB_APP_SLUG "App slug (the name in github.com/apps/<slug>)"
  ask GITHUB_APP_CLIENT_ID "Client ID"
  ask GITHUB_APP_CLIENT_SECRET "Client secret" secret
  read -r -p "Path to the downloaded private key .pem file: " pem
  [ -f "$pem" ] || die "no file at $pem"
  # The container cannot see host paths, so the key goes in as one line with literal \n, which the app accepts.
  put GITHUB_APP_PRIVATE_KEY "$(awk 'NF {printf "%s\\n", $0}' "$pem")"
  say "Saved. Restarting the app."
  docker restart custody-core >/dev/null
  sleep 5
  health
  echo "Check that it shows github_app_configured true and secret_scanner installed."
  exit 0
fi

# ---------------------------------------------------------------------------------------------------------------
say "1/6  Memory check"
mem_mb="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)"
swap_mb="$(awk '/SwapTotal/ {printf "%d", $2/1024}' /proc/meminfo)"
if [ "$mem_mb" -lt 3000 ] && [ "$swap_mb" -lt 1000 ]; then
  echo "This server has ${mem_mb} MB of memory and no swap; building the app can run out of memory. Adding 2 GB of swap."
  if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile; mkswap /swapfile >/dev/null
  fi
  swapon /swapfile 2>/dev/null || true
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
else
  echo "Fine (${mem_mb} MB memory, ${swap_mb} MB swap)."
fi

say "2/6  Your settings"
echo "Where to find them: Supabase dashboard > Project Settings > API (URL and anon key) and"
echo "Project Settings > Database > Connection string > Session pooler (the DATABASE_URL, with your database password filled in)."
ask DOMAIN "Domain name pointing at this server (e.g. custody.example.com, no https://)"
DOMAIN="$(get DOMAIN | sed 's#^https\?://##; s#/.*$##')"
put DOMAIN "$DOMAIN"
put APP_URL "https://$DOMAIN"
ask SUPABASE_URL "Supabase Project URL (https://<ref>.supabase.co)"
ask SUPABASE_ANON_KEY "Supabase anon / publishable key"
ask DATABASE_URL "Database connection string (Session pooler)" secret
# Never the service_role / secret key. Nothing here uses it.

if [ -z "$(get APP_DB_PASSWORD)" ]; then put APP_DB_PASSWORD "$(openssl rand -base64 24 | tr -d '\n')"; fi
if [ -z "$(get MFA_ENCRYPTION_KEY)" ]; then
  put MFA_ENCRYPTION_KEY "$(openssl rand -base64 32 | tr -d '\n')"
  NEW_MFA=1
fi
put SUPABASE_URL "$(get SUPABASE_URL)"
put VITE_SUPABASE_URL "$(get SUPABASE_URL)"
put VITE_SUPABASE_ANON_KEY "$(get SUPABASE_ANON_KEY)"
put BACKUP_DIR "/data/backups"

say "3/6  Does the domain point at this server?"
server_ip="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
domain_ip="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
echo "  This server: ${server_ip:-unknown}    $DOMAIN points at: ${domain_ip:-nothing yet}"
if [ -n "$server_ip" ] && [ "$server_ip" != "$domain_ip" ]; then
  echo "  They differ. Add an A record for $DOMAIN pointing at $server_ip, then wait a few minutes."
  echo "  Without it Caddy cannot get an https certificate."
  read -r -p "  Continue anyway? [y/N] " go
  [ "${go:-n}" = "y" ] || die "fix the DNS record, then run this script again (your answers are saved)."
fi

say "4/6  Building the app (a few minutes the first time)"
docker build \
  --build-arg "VITE_SUPABASE_URL=$(get VITE_SUPABASE_URL)" \
  --build-arg "VITE_SUPABASE_ANON_KEY=$(get VITE_SUPABASE_ANON_KEY)" \
  -t "$IMAGE" "$REPO_DIR"

say "5/6  Starting Custody Core"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker volume inspect custody-data >/dev/null 2>&1 || docker volume create custody-data >/dev/null
docker rm -f custody-core >/dev/null 2>&1 || true
# No published port: only Caddy, on the same private network, can reach the app. Settings are passed as an env
# file at run time, so no secret is stored in an image layer.
docker run -d --name custody-core --restart unless-stopped --network "$NET" \
  -v custody-data:/data --env-file "$ENV_FILE" "$IMAGE" >/dev/null

cat > "$DIR/Caddyfile" <<EOF
$DOMAIN {
    reverse_proxy custody-core:3000
}
EOF
docker rm -f custody-caddy >/dev/null 2>&1 || true
docker run -d --name custody-caddy --restart unless-stopped --network "$NET" \
  -p 80:80 -p 443:443 \
  -v "$DIR/Caddyfile:/etc/caddy/Caddyfile:ro" -v custody-caddy-data:/data caddy:2 >/dev/null

say "6/6  Waiting for it to answer (https certificate can take up to a minute)"
ok=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 8 "https://$DOMAIN/api/v1/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 4
done
if [ "$ok" -eq 1 ]; then
  health
  echo "Custody Core is running at https://$DOMAIN"
else
  echo "No answer yet. Look at the app's log:  docker logs --tail 60 custody-core"
  echo "and Caddy's:                           docker logs --tail 40 custody-caddy"
  echo "Common causes: the DNS record has not spread yet; ports 80 and 443 are blocked by a firewall;"
  echo "the DATABASE_URL is wrong (the app log says so)."
fi

cat <<EOF

Next:
  - Supabase > Authentication > URL Configuration: set the Site URL to https://$DOMAIN
  - Supabase > Authentication > Sign In / Providers > Email: turn "Confirm email" ON.
  - Sign up, confirm the email, set up the authenticator, claim a test project.
  - Add the GitHub App when ready:   sudo bash docs/deploy/setup-server.sh github
  - Check on it any time:            sudo bash docs/deploy/setup-server.sh status
  - Update after new code:           git pull && sudo bash docs/deploy/setup-server.sh
EOF

if [ "${NEW_MFA:-0}" = "1" ]; then
  cat <<EOF

IMPORTANT: copy this key somewhere safe now (a password manager). If it is lost, everyone must set up their
authenticator app again. It is also in $ENV_FILE.
  MFA_ENCRYPTION_KEY=$(get MFA_ENCRYPTION_KEY)
EOF
fi
