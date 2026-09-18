# paac — Portable Agent Authorization Control Plane

Vendor-neutral authorization layer for AI agents. **The LLM interprets; a deterministic policy engine alone grants `ALLOW` | `DENY` | `REVIEW`.**

Huge integration surface. Tiny trust core.

## Quickstart (CEO expense DENY demo)

```bash
# from repo root
cargo build -p authz-cli

# load example policies
cp examples/policies/hr_travel.dsl data/policies/active.dsl

# validate → commit → sign → deploy
./target/debug/authz policy validate
./target/debug/authz policy commit -m "Restrict executive expenses"
./target/debug/authz policy sign
./target/debug/authz policy deploy

# Head of HR asks: "How much did the CEO spend on trips last week?"
./target/debug/authz check \
  --principal user:hr-head \
  --role HR_HEAD \
  --action READ \
  --resource TRAVEL_EXPENSE \
  --subject employee:CEO \
  --subject-group EXECUTIVE \
  --direct-report employee:alice
```

Expected: **`DECISION: Deny`** with `policy_revision` and matched `executive_expense` evidence. Exit code `2`.

Natural-language path (mock llm-bridge constructs the request; engine still decides):

```bash
./target/debug/authz check \
  --principal user:hr-head \
  --role HR_HEAD \
  --action READ \
  --resource TRAVEL_EXPENSE \
  --nl "How much did the CEO spend on trips last week?"
```

## LDAP / mock identity → draft policies

```bash
./target/debug/authz identity sync ldap --drafts
./target/debug/authz suggest
ls data/policies/drafts/
```

Drafts are **never auto-deployed**. Humans validate, commit, sign, deploy.

## HTTP gateway smoke test

```bash
cargo build -p authz-gateway
./target/debug/authz-gateway --listen 127.0.0.1:8080 &
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d @examples/fixtures/ceo_expense_deny.json | jq .
# board UI
open http://127.0.0.1:8080/v1/board   # or browse that URL
```

## Crate map

| Crate | Role |
|-------|------|
| `authz-core` | `AuthzRequest`, Cedar evaluator wrapper, evidence, deny-by-default |
| `authz-policy` | Human DSL → Cedar, validate, versioned store, Ed25519 signed bundles |
| `authz-identity` | Identity model + local fixtures + JWT/OIDC normalize + LDAP (mock) adapter |
| `authz-suggest` | Draft suggestions from LDAP sync + audit history |
| `authz-gateway` | Axum HTTP: `POST /v1/check`, `GET /v1/explain/{id}`, health, board |
| `authz-cli` | Binary `authz` — identity, policy lifecycle, check, explain, suggest |
| `authz-board` | Minimal static matrix UI (served by gateway) |
| `authz-llm-bridge` | NL → `AuthzRequest` trait + mock provider (**never** evaluates policy) |

## Design locks

1. Small human DSL → Amazon Cedar (`cedar-policy`). Deny-by-default.
2. Relationships: `manager_of`, `direct_reports`, group membership, delegation.
3. NL only for request construction (`authz-llm-bridge`), never policy eval.
4. Canonical request: principal, action, resource, subject, context, relationships, `acting_as` / `on_behalf_of`.
5. CLI primary; minimal web board.
6. Identity: fixtures, JWT claims normalize, LDAP sync that generates **DRAFT** policies only.
7. `authz-suggest` proposes drafts; humans commit.
8. Ed25519 signed policy bundles; local key for MVP; `BundleSigner` trait is KMS-friendly.

## Policy DSL examples

See `examples/policies/hr_travel.dsl`.

## Tests

```bash
cargo test --workspace
./target/debug/authz policy test
```

## Optional OpenLDAP

```bash
docker compose up -d
# MVP uses mock LDAP by default; point a future live adapter at localhost:389
```

## License

MIT OR Apache-2.0
