# MEMORANDUM

**TO:** Chief Information Officer (CIO)  
**FROM:** Senior Security Engineer  
**DATE:** October 22, 2026  
**SUBJECT:** Intelligent Security Alert Triage Service — Architecture & Prototype  

---

### Executive Summary

Our security operations capacity is finite. Alert volumes continue to outpace staffing, yet automated response systems risk disrupting legitimate executive, engineering, and learner workflows when false positives occur. 

To address this, we developed a local **Security Triage Service** that accelerates the investigation of anomalous login alerts (such as new-country logins) without treating AI analysis as proof of compromise or granting it unmonitored containment authority.

---

### What Was Created & How It Works

The service exposes an authenticated HTTP endpoint (`POST /triage`) that evaluates incoming alerts against local identity and authentication telemetry. 

It implements a bounded, agentic workflow operating under strict architectural controls:
1. **Allowlisted Read-Only Tools**: The language model inspects only authorized telemetry—specifically identity context (role, environment, privilege) and recent authentication history (MFA evidence, country, timestamps).
2. **Deterministic Code Policy**: Ordinary application code—not the AI model—calculates investigation priority (`high`, `medium`, `low`, or `needs_review`). A privileged engineer logging in from an unfamiliar country is automatically prioritized as `high`. Unconfirmed data defaults to `needs_review`; the system never invents a low-risk classification.
3. **Strict Trust Boundaries**: Alert text and telemetry are treated strictly as untrusted data. Prompt injection attempts cannot override policy priority or invoke unapproved actions.
4. **Human-in-the-Loop Safeguards**: The model synthesizes an evidence-backed narrative, identifies uncertainties, and recommends investigative actions for human analysts. It cannot disable accounts or revoke tokens.

---

### What It Delivers

- **Rapid Analyst Decision Support**: Reduces manual investigation time from minutes to seconds by correlating identity privilege and authentication telemetry into a structured brief.
- **Safety by Design**: Eliminates hallucination risks by rejecting any AI output referencing non-existent evidence IDs.
- **Auditability**: Produces structured JSON detailing every tool invoked, observed evidence reference, and documented uncertainty.

---

### Next Steps

1. **Enterprise Telemetry Ingestion**: Replace synthetic local JSON stores with read-only connectors to our enterprise IdP (Okta) and SIEM (Snowflake/Splunk).
2. **Ticketing Integration**: Stream triage summaries directly into Jira Service Management or PagerDuty to guide Tier 1 SOC workflows.
3. **Analyst Feedback Loop**: Capture human investigator agreement rates to continuously refine detection rules and tool prompts.

---
*(Word count: 359 words)*
