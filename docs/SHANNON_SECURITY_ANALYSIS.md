# Shannon Security & Information-Theoretic Threat Model for PAAC

> **Framework**: Claude Shannon's Information Theory ($H(X)$, Mutual Information $I(X;Y)$, Equivocation $H(M|C)$) applied to Natural Language AI Authorization Boundaries.

---

## 1. The Fundamental Problem: Semantic Equivocation Gap $H(P \mid R_{prop})$

In a traditional deterministic system (e.g., REST API with OAuth2 scopes), the requested action and resource are explicitly typed:
$$\text{Request} = (\text{Action: READ}, \text{Resource: /v1/payroll/123})$$
Entropy of request interpretation: $H(\text{Intent} \mid \text{Request}) = 0$.

When an LLM or Natural Language interface is introduced:
$$\text{User Input Prompt } P \in \mathcal{P} \implies \text{Natural Language Extractor} \implies \text{AuthzRequest Proposal } R_{prop}$$

Because natural language is inherently ambiguous, high-dimensional, and subject to adversarial manipulation (prompt injection, obfuscation, homoglyphs, indirect jailbreaks), there exists a non-zero **Semantic Equivocation Gap**:
$$H(P \mid R_{prop}) > 0$$

An attacker's goal in a prompt injection attack is to maximize the divergence between the true side-effect intended by the prompt ($P$) and the benign proposal generated for Cedar ($R_{prop}$):
$$\Delta I = I(P; \text{SideEffect}) - I(R_{prop}; \text{CedarPolicy})$$

---

## 2. Information-Theoretic Bounds of PAAC's Defense-in-Depth

To guarantee that information leakage $I(\text{Confidential Data}; \text{Output} \mid \text{Policy} = \text{DENY}) = 0$, PAAC enforces a three-layer entropy reduction pipeline:

```
           High Entropy Unstructured Input (Prompt P)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Deterministic Entropy Reduction & Proposal Binding │
│ Maps unconstrained prompt P to finite Cedar schema types    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Zero-Equivocation Cedar Policy Kernel (AWS Cedar)  │
│ H(Decision | Policy, Principal, Context) = 0                │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Post-Generation Tool Parameter Entropy Filter      │
│ Intercepts LLM tool_calls & validates JSON arguments        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Parameter Entropy Reduction ($H(\text{Args})$ Bounds)

When an LLM outputs tool execution calls (e.g., `sql_query`, `export_payroll`, `retrieve_docs`), the tool parameters introduce arbitrary channel capacity:

$$C_{channel} = \max_{p(args)} I(\text{ToolArgs}; \text{Database Execution})$$

PAAC bounds parameter entropy via `authz-catalog`:
1. **Enumerated Tool Mappings**: Tools missing from `ResourceCatalog` map to `resource_kind: TOOL_UNKNOWN`. Since no policy permits `TOOL_UNKNOWN`, entropy drops to zero ($H(\text{Effect}) = 0 \implies \text{DENY}$).
2. **Argument Normalization**: Free-form JSON arguments are parsed, flattened, and validated against dynamic argument path rules (`arg_mappings`) before Cedar evaluation.

---

## 4. Non-Interference Proof & Multi-Boundary Isolation

PAAC enforces mathematical **Non-Interference** between security domains:

$$\text{Domain High (HR / Financial Data)} \quad \not\to \quad \text{Domain Low (Unprivileged User)}$$

- **Invariant 1**: An unprivileged principal $U_{low}$ producing prompt $P$ cannot cause Cedar to return `ALLOW` on a resource $R_{high}$ unless an explicit `permit` rule exists for $U_{low}$'s identity claims in the signed Cedar policy set.
- **Invariant 2**: Unclassified or low-confidence prompts map to `resource_kind: GENERAL_CHAT` or `UNKNOWN`. In a deny-by-default engine, unpermitted resources evaluate to `DENY` with $100\%$ determinism.
- **Invariant 3**: Cryptographic Policy Integrity — Policy sets are content-hashed (SHA-256) and Ed25519-signed. Tampering with a single byte in `active.dsl` or `active.cedar` causes an immediate cryptographic signature mismatch and server shutdown.

---

## 5. Precise Security Terminology Matrix

To maintain total rigor, PAAC documentation uses mathematically precise security terminology:

| Term | Mathematical / System Meaning in PAAC |
| :--- | :--- |
| **Deterministic Policy Kernel** | Given policy set $\mathcal{P}$, principal $S$, action $A$, resource $R$, and context $C$, Cedar evaluation returns $E \in \{\text{Allow}, \text{Deny}\}$ with zero randomness ($H(E) = 0$). |
| **Semantic Proposal Generator** | The NL extractor (`authz-llm-bridge`) emits a structured candidate request ($R_{prop}$); it holds **zero authority** to grant access. |
| **Signed Policy Bundle** | An Ed25519 digital signature over the SHA-256 digest of deployed policy files, guaranteeing authenticity and non-tampering. |
| **Signed Decision Audit Entry** | A structured audit record containing the request, Cedar decision, matched policy IDs, timestamp, and signature key ID. |
| **Fail-Closed Default** | In the absence of an explicit `permit` rule, the policy state defaults to $E = \text{Deny}$. |
