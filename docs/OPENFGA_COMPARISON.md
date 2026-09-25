# Architectural Comparison: PAAC vs. OpenFGA

> **Summary**: OpenFGA (CNCF Incubating, Google Zanzibar ReBAC) is a **centralized relationship database** for web application permissions. PAAC is an **inline AI reverse proxy and tool execution firewall** for LLMs & RAG applications.

---

## 1. High-Level Comparison Matrix

| Architectural Axis | OpenFGA (CNCF / Google Zanzibar) | PAAC (LLM Authorization Gateway) |
| :--- | :--- | :--- |
| **Primary Domain** | Application permissions for SaaS (Document sharing, Google Docs-style access). | **AI Safety & LLM Proxying** (Chat UIs, RAG databases, MCP Tool execution). |
| **Data Model** | **ReBAC** (Tuples: `user:anne` `reader` `document:123`). | **ABAC + RBAC** (AWS Cedar deterministic policy sets). |
| **Input Interface** | Formatted JSON/gRPC RPC payload specifying explicit IDs. | **OpenAI /v1 HTTP Proxy** accepting unstructured text prompts & SSE streams. |
| **Prompt Injection Protection** | ❌ None (Does not sit between client and LLM). | **Pre-Check Interception**: Evaluates prompt proposals before upstream LLM call. |
| **Tool Call Interception** | ❌ None (Cannot parse or modify LLM tool calls). | **Post-Check Interception**: Intercepts `tool_calls` and strips forbidden tools before execution. |
| **Deployment Model** | Distributed stateful service requiring MySQL / PostgreSQL storage backend. | **Stateless Proxy Sidecar** with in-memory Cedar evaluation (`ArcSwap`) & signed policy bundles. |

---

## 2. Why OpenFGA Cannot Replace PAAC for LLM Applications

### Problem A: The Prompt Equivocation Gap
When a user submits a prompt:
> *"Show me all executive travel expenses for last quarter."*

OpenFGA requires the application to **already know** the `object`, `relation`, and `user`. OpenFGA cannot parse natural language, extract target resource attributes (`TRAVEL_EXPENSE`, `subject: EXECUTIVE`), or handle prompt injection attempts.

PAAC includes `authz-llm-bridge` to translate natural language intent into a structured `AuthzRequest` proposal before executing Cedar policy checks.

### Problem B: Tool Call Interception & SSE Streaming
Modern AI chatbots generate dynamic tool calls (`sql_query`, `read_file`, `delete_account`) over Server-Sent Events (SSE). 

OpenFGA is a passive database: it cannot sit on an HTTP network connection, buffer streaming JSON chunks, evaluate tool arguments against policy rules, and strip unauthorized tool calls from the LLM response stream.

PAAC is an active **OpenAI-compatible reverse proxy (`paac-proxy`)** that filters model outputs in real time.

---

## 3. How PAAC Integrates with OpenFGA (Hybrid Architecture)

PAAC does not compete with OpenFGA for tuple storage. In an enterprise setting, PAAC acts as the **AI Gateway** on the edge, while OpenFGA acts as the **Upstream Relationship Store**:

```
Client (Chat UI)
       │
       │ HTTP /v1/chat/completions
       ▼
┌─────────────────────────────────────────────────────────────┐
│ PAAC Proxy (`paac-proxy`)                                   │
│  ├─ 1. Authenticate JWT / IdP                               │
│  ├─ 2. Extract NL Proposal (authz-llm-bridge)               │
│  ├─ 3. Local Cedar Policy Check                             │
│  └─ 4. (Optional) ReBAC Tuple Check ──► OpenFGA Engine      │
└──────────────┬──────────────────────────────────────────────┘
               │ (ALLOW)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Upstream LLM & Tool Connectors                              │
└─────────────────────────────────────────────────────────────┘
```
