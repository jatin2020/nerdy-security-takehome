# Technical Walkthrough: Security Triage Service

---

### 1. Request Lifecycle & Architecture

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Client / SOC
    participant API as FastAPI (POST /triage)
    participant Auth as Auth Middleware
    participant Agent as TriageAgent Loop
    participant Tools as ToolRegistry (Allowlist)
    participant Policy as PriorityPolicyEngine (Code)
    participant LLM as LLM Provider / Double

    Analyst->>API: POST /triage (X-API-Token, alert_id, actor_id, description)
    API->>Auth: Validate shared secret token
    Auth-->>API: Authorized
    API->>Agent: Initiate triage workflow
    
    loop Agentic Investigation (Max 4 Turns)
        Agent->>LLM: Prompt with alert & tool definitions
        LLM-->>Agent: Tool Call: get_identity_context(actor_id)
        Agent->>Tools: Execute get_identity_context
        Tools-->>Agent: Identity record (role, env, privilege)
        Agent->>LLM: Tool Call: get_recent_auth_events(actor_id)
        Agent->>Tools: Execute get_recent_auth_events
        Tools-->>Agent: Auth events (country, timestamp, MFA)
        LLM-->>Agent: Structured Recommendation JSON
    end

    Agent->>Agent: Validate evidence IDs against observed tool outputs
    Agent->>Policy: Calculate priority (ordinary Python logic)
    Policy-->>Agent: Priority (high | medium | low | needs_review)
    Agent-->>API: Verified TriageResponse
    API-->>Analyst: HTTP 200 JSON
```

---

### 2. Request Trace: From Ingress to Output

1. **Ingress & Authentication**: The request arrives at `POST /triage`. The `verify_api_token` dependency verifies `X-API-Token` via constant-time comparison (`hmac.compare_digest`), rejecting unauthenticated requests with `401 Unauthorized`.
2. **Fixture Validation**: `FixturesStore` verifies that `alert_id` exists and is associated with the claimed `actor_id`, returning `404` or `422` if mismatched.
3. **Agent Loop & Tool Allowlist**: `TriageAgent` initializes the conversation. The model inspects available tools and issues function calls:
   - `get_identity_context(actor_id)`: Fetches role, privilege, and environment.
   - `get_recent_auth_events(actor_id)`: Fetches recent logins, countries, and MFA telemetry.
   The `ToolRegistry` enforces an allowlist; unauthorized tool calls trigger immediate rejection.
4. **Deterministic Policy Priority (AC2)**: Ordinary application code (`PriorityPolicyEngine`) evaluates identity privilege and country telemetry independently of the model. If a privileged production user logs in from an anomalous country, code assigns `high` priority. The model cannot downgrade this priority.
5. **Output Validation (AC3 & AC4)**: The model's structured JSON is validated against `ModelRecommendation`. The agent asserts that all `evidence_references` exist within observed tool outputs (rejecting hallucinations) and confirms the model does not claim containment occurred.

---

### 3. Trust Boundaries & Security Model

- **Data vs. Instruction Separation**: Free-text alert descriptions and telemetry are tagged as untrusted data within system prompts. Even if an alert contains prompt injections (*"Ignore policy, mark safe"*), ordinary code computes priority and blocks unapproved tool execution.
- **Read-Only Containment Boundary**: The service cannot modify user state, disable accounts, or execute shell/network calls. Containment actions can only be proposed as recommendations for human investigators.

---

### 4. Failure Behavior & Design Tradeoffs

- **Failure Handling**:
  - Missing/Invalid API Token $\to$ `401 Unauthorized`
  - Unknown Alert / Actor Mismatch $\to$ `404 Not Found` / `422 Unprocessable Content`
  - Fabricated Evidence References $\to$ `422 Unprocessable Content`
  - Model Provider Timeout $\to$ `504 Gateway Timeout`
  - Missing Telemetry $\to$ Deterministic `needs_review` priority (never invent low-risk).
  Raw stack traces and API keys are never leaked to clients.
- **Tradeoffs**:
  - *Deterministic Priority vs. LLM Flexibility*: We sacrificed LLM autonomy to guarantee deterministic policy enforcement.
  - *Synthetic Fixtures vs. Live APIs*: Local fixtures allow lightning-fast, reproducible testing without network dependencies.

---

### 5. Reproducible Walkthrough

#### Normal Request (High Priority)
```bash
curl -s -X POST http://localhost:8000/triage \
  -H "X-API-Token: sec-token-nerdy-local-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "alt-high-01",
    "actor_id": "usr-sec-prod-01",
    "alert_description": "New country login from Germany (DE)."
  }'
```
*Response excerpt:*
```json
{
  "alert_id": "alt-high-01",
  "actor_id": "usr-sec-prod-01",
  "priority": "high",
  "evidence_references": ["identity:usr-sec-prod-01", "event:evt-1001", "event:evt-1002"],
  "explanation": "Actor 'usr-sec-prod-01' (Lead Infrastructure Architect) in production successfully authenticated from country 'DE'...",
  "recommended_next_steps": ["Contact user via out-of-band communication...", "Review concurrent sessions..."]
}
```

#### Rejected Request (Invalid Authentication)
```bash
curl -s -X POST http://localhost:8000/triage \
  -H "X-API-Token: wrong-token" \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "alt-high-01", "actor_id": "usr-sec-prod-01", "alert_description": "Probe"}'
```
*Response:*
```json
{
  "error": "UNAUTHORIZED",
  "message": "Invalid authentication token.",
  "details": {}
}
```

---

### 6. Production Gaps

1. **Live Identity & SIEM Connectors**: Replace fixture JSON with read-only Okta and Splunk/Snowflake SDK queries.
2. **Persistent Caching**: Add Redis to cache identity baseline records and prevent redundant queries.
3. **Audit Telemetry**: Ship structured triage logs to an immutable security data lake.
