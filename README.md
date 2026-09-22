# PAAC — LLM Authorization Gateway

> **Out-of-Band Policy Gateway & Tool Access Control for Enterprise LLMs**

[![Build & Test](https://img.shields.io/badge/build-passing-brightgreen)](#tests) [![Engine](https://img.shields.io/badge/engine-AWS%20Cedar-blue)](#crate-map) [![Threat Model](https://img.shields.io/badge/threat--model-Shannon--Entropy-orange)](docs/SHANNON_SECURITY_ANALYSIS.md)

📖 **Documentation**: [Executive & Product Overview](docs/PRODUCT_OVERVIEW.md) · [Information-Theoretic Security Analysis](docs/SHANNON_SECURITY_ANALYSIS.md) · [Architecture Guide](docs/ARCHITECTURE.md) · [Integration Guide](docs/INTEGRATION_GUIDE.md) · [Policy Guide](docs/POLICY_GUIDE.md) · [Security Model](docs/SECURITY.md)

---

### What is PAAC in Simple Terms?

#### 💡 For Management & Product Leaders
When your company connects an AI chatbot or AI agent to internal databases, **the AI model cannot be trusted to handle access permissions**. A clever user prompt can trick an LLM into revealing confidential executive salaries, financial records, or customer PII.

**PAAC (Policy-As-Access-Control)** is a high-performance **Security Firewall** sitting in front of your LLM. It intercepts every user prompt and AI tool call, checking them against mathematical security policies (**AWS Cedar**). If PAAC says `ALLOW`, data moves. If PAAC says `DENY`, the request is blocked instantly (**HTTP 403**) before touching your data or running tool calls.

#### 🧑‍💻 For Junior Developers (The "Smart Intern & Manager" Analogy)
Think of an LLM as a **brilliant Intern**: it can read documents, summarize text, and write SQL code, but it is naive and easily tricked by prompt injections.

**PAAC is the Strict Manager sitting at the door**:
1. When a user asks a question, PAAC checks their identity badge (JWT, LDAP, Entra ID).
2. PAAC checks the company rulebook: *"Does an intern have permission to access CEO payroll?"*
3. If **NO**, PAAC blocks the request immediately. The LLM never accesses the database.

---

### Request Flow

```
Client (Chat UI / App)
  │
  ▼
paac-proxy (OpenAI-compatible /v1/chat/completions, /v1/retrieve, MCP & A2A hooks)
  ├─ 1. Authenticate Principal (JWT / JWKS / IdP normalization)
  ├─ 2. NL → AuthzRequest Proposal (Structured Extraction + Resource Catalog)
  ├─ 3. Deterministic Cedar Eval (In-memory lock-free ArcSwap cache)
  ├─ 4. DENY ──► Return HTTP 403 Refusal + Audit Evidence (LLM & DB never called)
  └─ 5. ALLOW ──► Forward to Upstream LLM & Filter Tool Calls before execution
```

## Quick deploy in front of your LLM

```bash
cp paac.toml.example paac.toml
# set upstream.base_url to your vLLM/Ollama/LiteLLM OpenAI base (no trailing /v1 needed beyond config)
export PAAC_UPSTREAM_URL=http://127.0.0.1:8000
export PAAC_JWT_SECRET=your-hs256-secret
export PAAC_MODE=production   # rejects unsigned bundles + spoofable headers

# Policy lifecycle (human commit)
cp examples/policies/llm_data_rbac.dsl data/policies/active.dsl
cargo run -p authz-cli -- policy validate
cargo run -p authz-cli -- policy commit -m "company LLM RBAC v1"
cargo run -p authz-cli -- policy sign
cargo run -p authz-cli -- policy deploy

cargo run -p authz-llm-proxy -- --config paac.toml --listen 0.0.0.0:8080
```

Point your chat UI at `http://paac-host:8080/v1` instead of the LLM.

### Demo: DENY (CEO expenses)

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-paac-user: user:hr-head' -H 'x-paac-roles: HR_HEAD' \
  -d '{"model":"local","messages":[{"role":"user","content":"How much did the CEO spend on trips last week?"}]}'
# → HTTP 403, error.code=paac_deny, decision_id for `authz explain`
```

### Demo: ALLOW (direct report)

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-paac-user: user:hr-head' -H 'x-paac-roles: HR_HEAD' \
  -d '{"model":"local","messages":[{"role":"user","content":"show alice travel expenses"}]}'
```

Production identity: `Authorization: Bearer <JWT>` with `roles`/`groups` claims (HMAC or JWKS).

## Crate map

| Crate | Role |
|-------|------|
| `authz-core` | Embeddable kernel: newtypes, builders, Cedar eval, ArcSwap `BundleCache` |
| `authz-policy` | DSL → Cedar, Ed25519 signed bundles (content digest + verify) |
| `authz-identity` | LDAP (live+mock), AD, Entra ID, Cognito, JWT/JWKS, identity cache, draft generators |
| `authz-catalog` | YAML/JSON resource + tool→resource mappings |
| `authz-llm-bridge` | NL structured extraction → AuthzRequest **proposal only** |
| `authz-store` | SQLite: audit buffer, evidence index, identity/policy metadata |
| `authz-llm-proxy` | Binary `paac-proxy` — OpenAI proxy, MCP/A2A hooks, connectors |
| `authz-gateway` | Lightweight check/explain/board HTTP (still available) |
| `authz-cli` | `authz` — policy lifecycle, identity sync, catalog validate, proxy run helper |
| `authz-board` | Policy board UI: matrix + live audit + explain |
| `authz-suggest` | Draft suggestions + JSONL audit helpers |

## Identity sync → draft policies

```bash
cargo run -p authz-cli -- identity sync ldap --drafts
cargo run -p authz-cli -- identity sync entra --drafts
cargo run -p authz-cli -- identity sync cognito --drafts
cargo run -p authz-cli -- identity sync ad --drafts
# Drafts are NEVER auto-deployed. Humans validate → commit → sign → deploy.
```

## Performance notes

- Authz hot path: in-memory Cedar `PolicySet` behind `arc_swap::ArcSwap` (no lock on check).
- No LLM on the authorization critical path (extraction is deterministic regex/heuristics; optional LLM proposal must be revalidated).
- SQLite audit writes are buffered on a background thread; checks do not wait on fsync.
- Target: sub-millisecond p50 local eval for typical bundles; document p99 under load in your environment with `/metrics`.

## Fail-closed checklist (production)

- [ ] `mode = "production"`
- [ ] Signed policy bundle deployed; `/ready` shows `signed: true`
- [ ] JWT secret or JWKS configured; header identity disabled
- [ ] Upstream LLM only reachable via `paac-proxy`
- [ ] Catalog covers tools + tables/collections used by agents
- [ ] Audit SQLite/JSONL retained for evidence
- [ ] Chat UI base URL points at PAAC, not the model

## Ops

- `docker-compose.prod.yml` — proxy + WireMock LLM (+ optional OpenLDAP profile)
- `deploy/systemd/paac-proxy.service`
- Health: `GET /health` · Ready: `GET /ready` · Metrics: `GET /metrics`
- Board: `GET /v1/board`

## Embeddable SDK-ish usage

```rust
use authz_core::{evaluate, AuthzRequestBuilder, BundleCache, HotBundle};

let req = AuthzRequestBuilder::new()
    .principal("user:hr-head", vec!["HR_HEAD".into()])?
    .action("READ")?
    .resource_kind("TRAVEL_EXPENSE")?
    .subject("employee:CEO", vec!["EXECUTIVE".into()])?
    .build()?;
let decision = evaluate(&req, &bundle_cache.evaluator_config())?;
```

## Tests

```bash
cargo test --workspace
```

Includes proxy integration tests with a mock upstream LLM: NL DENY without data access, authorized upstream call, tool_call filtering, production header spoof rejection, concurrent checks.
