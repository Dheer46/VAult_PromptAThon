#!/bin/sh
# Bootstraps Keystone, creates the users Vault needs, then serves the public API on :5000.
set -e
# The catalog advertises http://keystone:5000; make sure that name reaches this container
# even when it runs under another name (the openstack CLI follows the catalog URL).
getent hosts keystone >/dev/null 2>&1 || echo "127.0.0.1 keystone" >> /etc/hosts
until mysql -h keystone-db -ukeystone -pkeystone -e "select 1" keystone >/dev/null 2>&1; do
  echo "waiting for keystone-db"; sleep 2
done
keystone-manage db_sync
keystone-manage fernet_setup --keystone-user root --keystone-group root
keystone-manage credential_setup --keystone-user root --keystone-group root
keystone-manage bootstrap --bootstrap-password admin-secret \
  --bootstrap-admin-url http://keystone:5000/v3/ \
  --bootstrap-internal-url http://keystone:5000/v3/ \
  --bootstrap-public-url http://keystone:5000/v3/ \
  --bootstrap-region-id RegionOne

gunicorn --bind 0.0.0.0:5000 --workers 2 --chdir /opt/keystone wsgi:application &
PID=$!

export OS_AUTH_URL=http://localhost:5000/v3 OS_IDENTITY_API_VERSION=3 \
  OS_USERNAME=admin OS_PASSWORD=admin-secret OS_PROJECT_NAME=admin \
  OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default
until curl -fs http://localhost:5000/v3 >/dev/null; do sleep 1; done
# service account Vault uses to validate user tokens (arrow #17)
openstack project show service >/dev/null 2>&1 || openstack project create --domain default service
openstack user show vault-service >/dev/null 2>&1 || \
  openstack user create --domain default --password service-secret vault-service
openstack role add --project service --user vault-service admin || true
# demo project + users: member -> readwrite, reader -> readonly
openstack project show demo >/dev/null 2>&1 || openstack project create --domain default demo
openstack user show demo >/dev/null 2>&1 || openstack user create --domain default --password demo-secret demo
openstack role add --project demo --user demo member || true
openstack user show demo-reader >/dev/null 2>&1 || \
  openstack user create --domain default --password reader-secret demo-reader
openstack role add --project demo --user demo-reader reader || true
echo "keystone ready: users demo/demo-secret (member), demo-reader/reader-secret (reader)"
wait $PID
