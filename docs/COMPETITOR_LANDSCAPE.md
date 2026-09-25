# Competitive Landscape: PAAC vs. Industry Alternatives

> **Overview**: Analysis of how PAAC compares against **LLM Gateways** (LiteLLM, Portkey), **AI Firewalls & Guardrails** (Lakera Guard, NVIDIA NeMo), **Relationship Engines** (OpenFGA, Permify), and **Policy Decision Points** (Cerbos, OPA).

---

## 1. Competitive Category Matrix

```
                          COMPETITOR CATEGORY MAP

   Category 1: Policy Engines             Category 2: AI Firewalls
   (Cerbos, OPA, OpenFGA)                 (Lakera Guard, NeMo, Llama Guard)
   • Deterministic permissions            • Statistical safety classifiers
   • Passive API (No LLM proxy)           • Prompt injection detection
   • No prompt parsing / tool filtering   • No user RBAC / ABAC awareness
              │                                      │
              └──────────────────┬───────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      PAAC GATEWAY       │
                    │  (Identity + Cedar +    │
                    │   Two-Phase Tool Guard) │
                    └─────────────────────────┘
                                 ▲
                                 │
                   Category 3: LLM Gateways
                   (LiteLLM, Portkey, Cloudflare)
                   • Model routing & fallbacks
                   • Token cost tracking & rate limits
                   • No enterprise authorization
```

---

## 2. Detailed Competitor Comparison Table

| Product | Category | Primary Focus | Identity-Bound RBAC/ABAC | Inline Tool Interception | Deterministic Policy Kernel | OpenAI Proxy & SSE |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **PAAC** | **AI Security Gateway** | **Enterprise data authorization & tool firewall** | ✅ **Yes** | ✅ **Yes (Pre & Post)** | ✅ **AWS Cedar** | ✅ **Yes** |
| **LiteLLM** | LLM Gateway | Model routing, fallbacks, token budgets | ❌ No | ❌ No | ❌ No | ✅ Yes |
| **Portkey** | AI Gateway | Observability, caching, enterprise routing | ❌ No | ❌ No | ❌ No | ✅ Yes |
| **Lakera Guard** | AI Security Firewall | Prompt injection & jailbreak ML detection | ❌ No | ❌ No | ❌ Statistical ML | ❌ No |
| **NVIDIA NeMo** | AI Guardrails | Dialog flow control & conversational safety | ❌ No | ❌ Partial (Colang) | ❌ Flow DSL | ❌ No |
| **Cerbos** | Policy Engine | Microservice authorization PDP | ✅ Yes | ❌ No | ✅ Custom DSL | ❌ No |
| **OPA / Styra** | Policy Engine | Cloud native microservice policy | ✅ Yes | ❌ No | ✅ Rego | ❌ No |
| **OpenFGA** | ReBAC Engine | Graph relationship store (Zanzibar) | ✅ ReBAC | ❌ No | ✅ Tuples | ❌ No |

---

## 3. Deep-Dive Comparison by Category

### Category 1: Traditional Policy Engines (Cerbos, OPA, OpenFGA)
- **How they work**: Microservices send a structured request (`user:alice`, `action:read`, `resource:doc123`). The engine returns `true` or `false`.
- **Where they fail for AI**:
  1. **Passive API**: They do not sit on the network between the user, the LLM, and the tool execution service.
  2. **No Prompt Awareness**: They cannot parse natural language queries or map prompt proposals to resources.
  3. **No Tool Output Interception**: They cannot inspect JSON responses emitted by LLMs to strip forbidden tool calls.
- **PAAC's Value**: PAAC wraps **AWS Cedar** in an **inline HTTP/SSE reverse proxy**, providing natural language proposal mapping (`authz-llm-bridge`) and tool call filtering (`filter_tool_calls`).

### Category 2: AI Firewalls & Safety Guardrails (Lakera Guard, NVIDIA NeMo, Llama Guard)
- **How they work**: Statistical ML models scan input text for prompt injections, jailbreaks, PII, or toxic content.
- **Where they fail for Enterprise Data**:
  1. **No User Authorization Context**: Lakera or Llama Guard might report a prompt is "safe", but they **do not know who the user is** or whether they have permission to access CEO payroll data.
  2. **Statistical Unreliability**: ML classifiers can be bypassed with obfuscated text or novel injection techniques.
- **PAAC's Value**: PAAC uses **deterministic AWS Cedar policies** combined with user identity claims (JWT, LDAP, Entra ID). Even if a prompt injection bypasses a safety classifier, Cedar evaluates the user's role against the target resource and returns a strict **HTTP 403 DENY**.

### Category 3: LLM Infrastructure Gateways (LiteLLM, Portkey, Cloudflare AI Gateway)
- **How they work**: Proxy servers that route requests across OpenAI, Anthropic, vLLM, and Ollama to handle failover, load balancing, latency tracking, and cost management.
- **Where they fail for Security**:
  1. **Traffic Routers, Not Access Controls**: They pass prompts directly to the model without evaluating user authorization rules or tool access boundaries.
- **PAAC's Value**: PAAC functions as a **security-first gateway**. It can be deployed upstream of LiteLLM/Portkey to ensure only authorized prompts and tool calls reach downstream routing infrastructure.

---

## 4. Key Differentiator Summary for PAAC

1. **Identity-Bound Zero-Trust**: Security decisions are tied directly to authenticated enterprise user identity claims (JWT/JWKS, AD, LDAP, Entra ID, SAML 2.0).
2. **Two-Phase Interception**: Evaluates user prompts *before* calling the LLM and intercepts model `tool_calls` *before* data connectors execute.
3. **Deterministic Cedar Engine**: Policy checks run in-memory behind lock-free atomic pointers (`ArcSwap`) with Ed25519-signed policy bundles.
