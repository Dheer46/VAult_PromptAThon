#!/usr/bin/env bash
# Runs one Vault storage node on EC2 with its EBS drives bind-mounted.
# Usage: ./run-node.sh node1
set -euo pipefail
NODE=${1:?node name, e.g. node1}
SERVICES=${SERVICES:-10.42.1.10}
grep -q "node1" /etc/hosts || cat >> /etc/hosts <<EOF
10.42.1.11 node1
10.42.1.12 node2
10.42.1.13 node3
10.42.1.14 node4
$SERVICES services
EOF
docker rm -f vault 2>/dev/null || true
docker run -d --name vault --restart always --network host --cap-add NET_ADMIN \
  -v /data/disk1:/data/disk1 -v /data/disk2:/data/disk2 -v /data/disk3:/data/disk3 -v /data/disk4:/data/disk4 \
  -v /var/log/vault:/var/log/vault \
  -e VAULT_NODE_NAME="$NODE" -e VAULT_NODES="http://node{1...4}:9000" -e VAULT_DRIVES="/data/disk{1...4}" \
  -e VAULT_SET_SIZE=8 -e VAULT_DEFAULT_PARITY=3 \
  -e VAULT_ROOT_USER="${VAULT_ROOT_USER:-vaultadmin}" -e VAULT_ROOT_PASSWORD="${VAULT_ROOT_PASSWORD:?set}" \
  -e VAULT_CLUSTER_SECRET="${VAULT_CLUSTER_SECRET:?set}" \
  -e VAULT_KMS_ADDR="http://services:8200" -e VAULT_KMS_TOKEN="${VAULT_KMS_TOKEN:?set}" \
  -e VAULT_KEYSTONE_URL="http://services:5000" -e VAULT_KEYSTONE_SERVICE_USER=vault-service \
  -e VAULT_KEYSTONE_SERVICE_PASSWORD="${KEYSTONE_SERVICE_PASSWORD:-service-secret}" \
  -e VAULT_EVENT_WEBHOOK="http://services:8080/events" -e VAULT_EVENT_KAFKA="services:9092/vault-events" \
  -e VAULT_AUDIT_WEBHOOK="http://services:8080/audit" -e VAULT_AUDIT_FILE=/var/log/vault/audit.jsonl \
  vault:latest
