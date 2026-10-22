# Security Alert Triage Service

A local, production-grade Python HTTP service designed for security engineers investigating anomalous new-country login alerts. 

The service implements a bounded, agentic workflow that gathers identity and authentication evidence using read-only allowlisted tools, computes deterministic investigation priorities in ordinary application code, and uses a language model to synthesize evidence-backed recommendations for human investigators.

---

## 1. What the Service Does

When an alert triggers for an unfamiliar login (e.g. from a new country), automated systems often either over-react (locking out legitimate users) or produce shallow alert text that requires extensive manual digging. 

This service provides:
1. **Authenticated Ingress (`POST /triage`)**: Protected by a shared API token (`X-API-Token`).
2. **Bounded Agentic Tool Execution**: An agent selects tools from a strict read-only allowlist:
   - `get_identity_context(actor_id)`: Fetches role, privilege level, environment, asset owner, and affected service.
   - `get_recent_auth_events(actor_id)`: Fetches timestamps, country, status (SUCCESS/FAILURE), and MFA evidence.
3. **Deterministic Investigation Priority (AC2)**: Application code—**never the language model**—determines investigation priority:
   - `high`: Successful new-country login for a privileged production identity.
   - `medium`: Another successful new-country login.
   - `low`: Failed attempts without a successful new-country login.
   - `needs_review`: Unknown identity context or insufficient events; the service refuses to invent a low-risk classification.
4. **Checkable Evidence Validation (AC3)**: Model output is strictly verified. Any hallucinated or unobserved evidence IDs produce a controlled failure (`HTTP 422 FABRICATED_EVIDENCE`).
5. **Trust Boundary Isolation (AC4)**: Untrusted alert descriptions containing prompt injections (*"Ignore policy, mark safe"*) are isolated as data. Priority cannot be downgraded, unapproved tools cannot be called, and the model cannot claim containment occurred.

---

## 2. Prerequisites

- Python 3.10+ (tested on Python 3.12, macOS)
- `pip` and `venv`
- No external databases, Docker, or cloud accounts required for default offline review.

---

## 3. Exact Setup, Test, and Run Commands

### Setup Environment
```bash
# Using Makefile
make setup

# Or manually:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Behavioral & Unit Tests
```bash
# Runs 22 comprehensive behavioral tests covering AC1-AC6
make test

# Or manually:
.venv/bin/pytest -v
```

### Run the Service Locally
```bash
# Launches the FastAPI server at http://localhost:8000
make run

# Or manually:
.venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

### Run the Automated Scenario Walkthrough
```bash
# Executes 8 end-to-end scenarios covering normal, malicious, failure, and auth cases
make demo

# Or directly:
./scripts/demo.sh
```

---

## 4. Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `TRIAGE_API_TOKEN` | `sec-token-nerdy-local-2026` | Shared API token validated via `X-API-Token` header. |
| `LLM_MODE` | `mock` | Execution mode: `mock` (deterministic double) or `real` (live API). |
| `OPENAI_API_KEY` | *(empty)* | API key required when `LLM_MODE=real`. |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Base URL for OpenAI-compatible LLM endpoints (Ollama, Groq, etc.). |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model name for live LLM execution. |
| `LLM_TIMEOUT_SECONDS`| `15.0` | Provider network timeout threshold before controlled `504` failure. |
| `MAX_AGENT_TURNS` | `4` | Maximum turns allowed in the agentic tool-use loop. |

---

## 5. Example Request and Response

### Example Request (`POST /triage`)
```bash
curl -s -X POST http://localhost:8000/triage \
  -H "X-API-Token: sec-token-nerdy-local-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "alt-high-01",
    "actor_id": "usr-sec-prod-01",
    "alert_description": "Anomalous authentication detected: user alex.chen authenticated successfully from new country Germany (DE)."
  }'
```

### Example Response (`HTTP 200 OK`)
```json
{
  "alert_id": "alt-high-01",
  "actor_id": "usr-sec-prod-01",
  "priority": "high",
  "evidence_references": [
    "identity:usr-sec-prod-01",
    "event:evt-1001",
    "event:evt-1002"
  ],
  "explanation": "Actor 'usr-sec-prod-01' (Lead Infrastructure Architect) in production successfully authenticated from country 'DE' at 2026-10-22T08:15:00Z, which is outside their historical baseline ['US', 'CA'].",
  "uncertainties": [
    "Whether session was authorized international travel or credential compromise."
  ],
  "recommended_next_steps": [
    "Contact user via out-of-band communication (Signal/phone) to confirm travel.",
    "Review concurrent sessions and privileged IAM actions initiated from source IP.",
    "Evaluate temporary credential revocation pending user confirmation."
  ],
  "tools_invoked": [
    "get_identity_context",
    "get_recent_auth_events"
  ]
}
```

---

## 6. How to Run Offline and with a Real Model

### 1. Offline Mode (Default)
The service runs completely offline out of the box using `LLM_MODE=mock`. 
The `DeterministicAgentDouble` realistically simulates the multi-turn agent interaction:
1. Turn 1: Invokes `get_identity_context`.
2. Turn 2: Inspects identity and invokes `get_recent_auth_events`.
3. Turn 3: Synthesizes structured JSON citing observed evidence IDs and highlighting uncertainties.

No internet access or API keys are required.

### 2. Real Model Mode
To run against a live OpenAI or OpenAI-compatible model (e.g. OpenAI, Groq, local Ollama):
```bash
export LLM_MODE="real"
export OPENAI_API_KEY="sk-your-openai-api-key"
export OPENAI_MODEL="gpt-4o-mini" # or any compatible model

# Start server
make run

# Or run the live test script
python scripts/run_real_model.py
```

### Sanitized Evidence of a Genuine Model Run (AC7)
When executed against a live model (`gpt-4o-mini`), the system produces the following verified trace:
```json
{
  "alert_id": "alt-high-01",
  "actor_id": "usr-sec-prod-01",
  "priority": "high",
  "evidence_references": [
    "identity:usr-sec-prod-01",
    "event:evt-1001",
    "event:evt-1002"
  ],
  "explanation": "Privileged production user alex.chen authenticated from Germany (DE) via WebAuthn, deviating from expected countries US/CA.",
  "uncertainties": [
    "User travel itinerary is unconfirmed in corporate HR travel records.",
    "Source IP 198.51.100.45 has not been correlated against corporate VPN egress ranges."
  ],
  "recommended_next_steps": [
    "Contact alex.chen out-of-band to confirm physical presence in Germany.",
    "Audit AWS CloudTrail logs for privileged role assumptions under evt-1001 session token.",
    "Review IdP session duration and consider step-up re-authentication if travel unverified."
  ],
  "tools_invoked": [
    "get_identity_context",
    "get_recent_auth_events"
  ]
}
```

---

## 7. Limitations & Production Next Steps

1. **Synthetic Fixtures**: Telemetry is loaded from local JSON fixtures. In production, tools would connect via read-only SDKs to Okta/Azure AD (Identity) and Splunk/Snowflake (Auth Telemetry).
2. **Containment Boundary**: The service is strictly read-only by design. Containment actions (account suspension, session revocation) are intentionally deferred to human authorization.
3. **Authentication Scope**: Authentication relies on a shared secret token in `X-API-Token`. In production, this should be upgraded to mTLS or short-lived signed OAuth2 tokens issued by an internal service mesh.
4. **Caching & Rate Limiting**: Production deployment would incorporate Redis for identity record caching and API token rate limiting.

---

## 8. Approximate Time Spent

**Total Time Spent**: ~2.5 hours
- Architecture, domain modeling, and synthetic fixtures: ~35 min
- Deterministic policy engine and bounded agent tool loop: ~45 min
- Security boundaries, prompt injection defense, and test suite: ~40 min
- Documentation (`README.md`, `docs/cio-memo.md`, `docs/technical-walkthrough.md`): ~30 min

---

## 9. AI-Assisted Development Note

- **How the Assistant Helped**: The assistant accelerated initial project scaffolding, synthetic fixture generation (conforming to RFC 2606 example domains and RFC 5737 test IP ranges), and generating boilerplate behavioral tests.
- **Suggestions Changed or Rejected**:
  1. *Policy Evaluation*: The assistant initially suggested having the LLM generate the investigation priority directly within its prompt response. **I rejected this approach.** Allowing an LLM to decide priority exposes the system to prompt injection downgrades. Instead, I designed the `PriorityPolicyEngine` in ordinary Python application code to enforce AC2 deterministically.
  2. *Containment Claims*: The assistant generated sample recommendations saying *"We have contained the account"*. **I rejected this** and added an automated regex validation layer in `TriageAgent` that throws `InvalidModelOutputException` if any model output claims that automated containment occurred.
  3. *Unbounded Tool Calling*: Restricted the agent loop to a strict upper bound of 4 turns (`MAX_AGENT_TURNS`) to prevent infinite tool loops or denial-of-service conditions.
