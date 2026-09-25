# Keystone for Vault (arrow #17: IAM and OIDC → Keystone Service)

The `keystone` container installs Keystone 26.0.0 (2024.2) from PyPI, serves the public API
with gunicorn on port 5000, and bootstraps itself against the `keystone-db` MariaDB container:

1. `keystone-manage db_sync`, `fernet_setup`, `credential_setup`, `bootstrap` (admin / `admin-secret`).
2. Creates project `service` and user `vault-service` / `service-secret` with the `admin` role.
   Vault uses this account to validate user tokens (`GET /v3/auth/tokens`).
3. Creates project `demo` with the users `demo` / `demo-secret` (role `member` → Vault policy
   `readwrite`) and `demo-reader` / `reader-secret` (role `reader` → Vault policy `readonly`).

Try it:

```bash
TOKEN=$(curl -si http://localhost:5000/v3/auth/tokens -H 'content-type: application/json' -d '{
  "auth":{"identity":{"methods":["password"],"password":{"user":{"name":"demo-reader",
  "domain":{"name":"Default"},"password":"reader-secret"}}},
  "scope":{"project":{"name":"demo","domain":{"name":"Default"}}}}}' | awk '/X-Subject-Token/{print $2}' | tr -d '\r')
curl -H "X-Auth-Token: $TOKEN" http://localhost:9000/            # lists buckets (reader)
curl -H "X-Auth-Token: $TOKEN" -X PUT http://localhost:9000/nope  # 403 AccessDenied
```

The WSGI entry point differs between Keystone releases; if you change the version, check the
install guide for that release (`deploy/keystone/wsgi.py` wraps `keystone.server.wsgi:initialize_public_application()` here).
