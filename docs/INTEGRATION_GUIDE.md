# PAAC Integration & API Reference Guide

PAAC provides drop-in OpenAI API compatibility alongside custom security and protocol endpoints.

---

## OpenAI API Compatibility

Point any standard OpenAI SDK client (Python, Node.js, LangChain, LlamaIndex) to PAAC by changing the `base_url`:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://paac-host:8080/v1",
    api_key="your-jwt-or-bearer-token"
)

response = client.chat.completions.create(
    model="local",
    messages=[{"role": "user", "content": "show alice travel expenses"}]
)
print(response.choices[0].message.content)
```

---

## API Endpoints

### 1. Chat Completions Proxy
`POST /v1/chat/completions`

Evaluates natural language intent before sending to upstream LLM, and intercepts returned `tool_calls`.

**Headers**:
- `Authorization`: `Bearer <JWT_TOKEN>` (Mandatory in production)
- `x-paac-user`: Principal user ID (Development mode only)
- `x-paac-roles`: Comma-separated roles (Development mode only)

**Refusal Response (HTTP 403)**:
```json
{
  "error": {
    "message": "PAAC denied access: READ on TRAVEL_EXPENSE (decision 4f9e2b10-7a31-4091-8b2c-9821a00a12e4)",
    "type": "paac_access_denied",
    "code": "paac_deny",
    "decision_id": "4f9e2b10-7a31-4091-8b2c-9821a00a12e4"
  }
}
```

---

### 2. RAG Retrieval Authorization
`POST /v1/retrieve`

Evaluates vector search or document retrieval permission for a collection.

**Request Body**:
```json
{
  "collection": "finance_filings",
  "document_id": "doc_2026_q2"
}
```

---

### 3. Model Context Protocol (MCP) Integration
`POST /v1/mcp/tools/call`

Authorizes MCP tool executions before delegating to tools.

**Request Body**:
```json
{
  "name": "sql_query",
  "arguments": {
    "table": "db.hr.employees",
    "sql": "SELECT * FROM employees"
  }
}
```

---

### 4. Agent-to-Agent (A2A) Authorization
`POST /v1/a2a/authorize`

Evaluates authorization for inter-agent communication messages.

---

### 5. Health, Readiness & Metrics
- `GET /health` — Service health status
- `GET /ready` — Policy bundle readiness and signing status
- `GET /metrics` — Prometheus metrics exporter

```prometheus
# TYPE paac_checks_total counter
paac_checks_total 128
# TYPE paac_denies_total counter
paac_denies_total 14
# TYPE paac_allows_total counter
paac_allows_total 114
# TYPE paac_upstream_calls counter
paac_upstream_calls 114
```
