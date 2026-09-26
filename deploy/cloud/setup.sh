#!/usr/bin/env bash
# One-command setup of the full Vault cluster on a fresh Ubuntu 22.04/24.04 server.
#
#   curl -fsSL https://raw.githubusercontent.com/Dheer46/VAult_PromptAThon/main/deploy/cloud/setup.sh | sudo bash
#
# Optional: DOMAIN=vault.example.com (default: <public-ip>.sslip.io, which needs no DNS).
# Needs: 2+ vCPU, 8 GB RAM, 40+ GB disk; inbound ports 22, 80 and 443 open.
set -euo pipefail

REPO=${REPO:-https://github.com/Dheer46/VAult_PromptAThon.git}
DIR=${DIR:-/opt/vault}

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

log "Installing Docker and git"
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi
apt-get update -qq && apt-get install -y -qq git openssl >/dev/null
systemctl enable --now docker >/dev/null

log "Fetching the code into $DIR"
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only; else git clone --depth 1 "$REPO" "$DIR"; fi
cd "$DIR"

ENV=deploy/cloud/.env
if [ ! -f "$ENV" ]; then
  log "Generating secrets (kept in $ENV, readable by root only)"
  IP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
  rnd() { openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }
  umask 077
  cat > "$ENV" <<EOF
DOMAIN=${DOMAIN:-${IP//./-}.sslip.io}
VAULT_ROOT_USER=vaultadmin
VAULT_ROOT_PASSWORD=$(rnd 28)
VAULT_CLUSTER_SECRET=$(rnd 40)
KMS_ROOT_TOKEN=$(rnd 32)
REMOTE_S3_SECRET=$(rnd 28)
GRAFANA_ADMIN_PASSWORD=$(rnd 20)
EOF
fi
set -a; . "$ENV"; set +a

if command -v ufw >/dev/null && ufw status | grep -q active; then
  log "Opening ports 80 and 443 in ufw"; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
fi

log "Building and starting the cluster (first build takes ~10 minutes)"
COMPOSE="docker compose -f deploy/docker-compose.yml -f deploy/cloud/docker-compose.cloud.yml --env-file $ENV"
$COMPOSE up -d --build

log "Waiting for https://$DOMAIN to become healthy"
for i in $(seq 1 120); do
  if curl -fsS "https://$DOMAIN/vault/health/cluster" >/dev/null 2>&1; then OK=1; break; fi
  sleep 5
done
[ "${OK:-}" = 1 ] || { echo "Not healthy yet. Check: $COMPOSE ps  and  $COMPOSE logs caddy node1"; exit 1; }

cat <<EOF

  Vault is live.

  Console:     https://$DOMAIN/vault/console
  S3 endpoint: https://$DOMAIN
  Admin login: vaultadmin / $VAULT_ROOT_PASSWORD
               (stored in $DIR/$ENV; keep it secret)

  Vercel: add this rewrite to vercel.json so the Vercel site uses this backend:
    { "source": "/vault/:path*", "destination": "https://$DOMAIN/vault/:path*" }

  Update later:  cd $DIR && git pull && $COMPOSE up -d --build
EOF
