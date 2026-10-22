"""Utility to run an anomalous alert triage against a live LLM endpoint.
Requires OPENAI_API_KEY environment variable.

Usage:
    export OPENAI_API_KEY="sk-..."
    python scripts/run_real_model.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from src.config import Settings
from src.main import app

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    print("\n[!] OPENAI_API_KEY environment variable is not set.")
    print("To run with a live model:")
    print("    export OPENAI_API_KEY=\"sk-...\"")
    print("    export OPENAI_MODEL=\"gpt-4o-mini\"  # optional")
    print("    python scripts/run_real_model.py\n")
    print("Running in offline/mock mode instead...\n")

# Configure environment for real LLM if key present
if api_key:
    os.environ["LLM_MODE"] = "real"

client = TestClient(app)
settings = Settings()

headers = {"X-API-Token": settings.triage_api_token}
payload = {
    "alert_id": "alt-high-01",
    "actor_id": "usr-sec-prod-01",
    "alert_description": "New country login detected for alex.chen from Germany (DE).",
}

print(f"Triggering /triage with LLM_MODE={settings.llm_mode}...")
resp = client.post("/triage", headers=headers, json=payload)
print(f"Status: {resp.status_code}")
print(resp.json())
