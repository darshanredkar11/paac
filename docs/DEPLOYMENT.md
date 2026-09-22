# PAAC Deployment & Operations Guide

This guide covers building, configuring, and operating PAAC in single-node and containerized enterprise environments.

---

## Deployment Options

### Option A: Docker Compose (Production Setup)

Deploy PAAC alongside an upstream LLM (or mock server) using `docker-compose.prod.yml`:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Option B: Binary Systemd Service

Deploy compiled `paac-proxy` binary on Linux host:

1. Copy compiled binary to `/usr/local/bin/paac-proxy`.
2. Copy service definition:
   ```bash
   cp deploy/systemd/paac-proxy.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now paac-proxy
   ```

---

## Configuration Reference (`paac.toml`)

```toml
[server]
listen = "0.0.0.0:8080"
mode = "production" # "production" or "development"

[upstream]
base_url = "http://127.0.0.1:8000"
timeout_secs = 30
api_key = "optional-upstream-llm-api-key"

[policy]
policy_dir = "data/policies"
require_signed_bundle = true

[catalog]
catalog_path = "data/catalog/company_resources.yaml"

[identity]
jwt_hmac_secret = "your-hs256-jwt-secret"
prefer_jwt_roles = true
allow_header_identity = false
cache_ttl_secs = 300

[connectors]
execute_tools = false
```

---

## Environment Variable Overrides

All settings in `paac.toml` can be overridden using environment variables:

| Variable | Description |
|---|---|
| `PAAC_MODE` | Set run mode (`production` or `development`). |
| `PAAC_UPSTREAM_URL` | Base URL of upstream LLM. |
| `PAAC_JWT_SECRET` | Secret key for JWT HMAC verification. |
| `PAAC_JWKS_URL` | Remote JWKS URL for OAuth2 / OIDC token verification. |
| `PAAC_LISTEN` | IP and port to listen on (`0.0.0.0:8080`). |
