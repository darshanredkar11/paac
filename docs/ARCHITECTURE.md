# PAAC (Policy-As-Access-Control) Architecture Guide

PAAC is an out-of-band **LLM Authorization Gateway** designed to protect enterprise production data from unauthorized LLM prompts, model hallucinations, and prompt injection attacks.

> 💡 **For Management & Product Overview**: See [`PRODUCT_OVERVIEW.md`](PRODUCT_OVERVIEW.md) for plain-language explanations, business value matrices, and real-world examples.

---

## High-Level System Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  Client (Chat UI / API / AI Agent)      │
                    └────────────────────┬────────────────────┘
                                         │
                                         │ HTTP /v1/chat/completions
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  PAAC PROXY (`authz-llm-proxy`)                                                 │
│                                                                                 │
│  ┌───────────────────────┐   ┌─────────────────────────┐   ┌─────────────────┐  │
│  │ 1. Principal Auth     │   │ 2. Intent Extraction    │   │ 3. Cedar Eval   │  │
│  │ (JWT / JWKS / IdP)    ├──►│ (authz-llm-bridge)    ├──►│ (authz-core)    │  │
│  └───────────────────────┘   └─────────────────────────┘   └────────┬────────┘  │
└─────────────────────────────────────────────────────────────────────────┼───────┘
                                                                          │
                                                ┌─────────────────────────┴──────┐
                                                │ Decision == ALLOW?             │
                                                └──────────┬──────────────┬──────┘
                                                           │              │
                                                   ALLOW   │              │ DENY
                                                           ▼              ▼
                                                ┌──────────────────┐  ┌──────────┐
                                                │ Call Upstream    │  │ HTTP 403 │
                                                │ LLM Endpoint     │  │ Refusal  │
                                                └──────────┬───────┘  └──────────┘
                                                           │
                                                           ▼
                                                ┌──────────────────┐
                                                │ Intercept Tools  │
                                                │ & Connectors     │
                                                └──────────────────┘
```

---

## Crate Inventory & Responsibilities

| Crate | Path | Responsibility |
|---|---|---|
| `authz-core` | `crates/authz-core` | Embeddable policy evaluation kernel, Cedar engine integration, `ArcSwap` lock-free hot cache, and structured decision evidence generator. |
| `authz-policy` | `crates/authz-policy` | Human-readable DSL parser, Cedar translation engine, and Ed25519 bundle signing & verification. |
| `authz-identity` | `crates/authz-identity` | IdP integration (LDAP, Active Directory, Entra ID, AWS Cognito), JWT HMAC/JWKS validation, and identity caching. |
| `authz-catalog` | `crates/authz-catalog` | Resource catalog management, tool-to-resource mappings, and RAG collection attribute resolution. |
| `authz-llm-bridge` | `crates/authz-llm-bridge` | Deterministic natural language intent extraction to form authorization proposals (`AuthzRequest`). |
| `authz-store` | `crates/authz-store` | Transactional SQLite audit logger and decision evidence index. |
| `authz-llm-proxy` | `crates/authz-llm-proxy` | Axum reverse proxy handling `/v1/chat/completions`, `/v1/retrieve`, MCP, and A2A hooks. |
| `authz-gateway` | `crates/authz-gateway` | Lightweight standalone HTTP check/explain server. |
| `authz-cli` | `crates/authz-cli` | Command-line policy management interface (`authz policy validate`, `commit`, `sign`, `deploy`). |
| `authz-board` | `crates/authz-board` | Web UI policy matrix dashboard and live decision inspector. |
| `authz-suggest` | `crates/authz-suggest` | Draft policy generation and audit log analytical helpers. |

---

## Core Principles & Guarantees

### 1. Fail-Closed & Deny-by-Default
If no explicit `permit` policy matches a request, or if an explicit `forbid` policy matches, PAAC returns a strict `DENY`. Upstream LLMs and data connectors are never invoked for denied requests.

### 2. Zero-Lock In-Memory Evaluation
Policy sets are evaluated in-memory using Cedar (`cedar-policy` v4). Deployed bundles are managed behind an `arc_swap::ArcSwap` atomic pointer, enabling lock-free policy checks on the hot path.

### 3. Cryptographic Policy Bundles
In production mode (`PAAC_MODE=production`), PAAC requires all policy bundles (`active.dsl` and `active.cedar`) to be cryptographically signed with Ed25519 signatures. Any policy tampering prevents server startup and hot reloading.

### 4. Two-Phase Tool Interception
1. **Phase 1 (Pre-Execution)**: Evaluates user intent before forwarding to the LLM.
2. **Phase 2 (Post-Generation)**: Evaluates model-generated `tool_calls` before executing data connectors, stripping forbidden actions from the choice payload.
