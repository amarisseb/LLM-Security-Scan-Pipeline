# Arisec

**Find out where your AI goes wrong, what to change and how to check the fix.**

Arisec helps teams assess an AI feature before they ship it. Connect an authorised application or model, run a security assessment and get a report that pairs flagged responses with a plain-English explanation, a concrete next step and a retest.

[Interactive sample report (download HTML)](sample_report.html) · [Run Arisec locally](#try-it-locally)

## What a finding gives you

In the sample report, a support assistant follows an instruction hidden in a customer message and abandons its summary. Arisec shows the response, explains why it went off task and recommends a specific change: keep the summary instruction in the application and pass the customer message separately. The action plan gives the team two checks to run afterwards. Replay the flagged message to see whether the assistant stays on task, then try an ordinary message to confirm the feature still works.

An early **GPT‑4o‑mini provider scan** recorded **2,135 task-hijacking detector matches across 3,840 evaluations**. Arisec’s separate audit command reproduced that count from the original scan records. Each match is a result to investigate. Application impact depends on what the AI can access or do.

## Implemented in the current preview

- **Assessment setup.** Connect a supported model provider for a baseline or a verified application JSON API to test application behaviour. Use the local preview to explore the interface.
- **Scanning.** The garak-based pipeline groups checks into task hijacking, jailbreaks, filter evasion, synthetic prompt extraction and unsafe content. Connector support varies by check. Synthetic prompt extraction tests disclosure of scanner-supplied instructions.
- **Findings and remediation.** Review detector matches, checks with no match, and categories the scan could not assess. Response evidence and plain-English guidance help developers choose a change and plan a retest.
- **Report verification.** The separate `audit_report.py` command recalculates the legacy HTML report's category totals from the original garak JSONL evaluation records. Detector matches are candidates for review. Establishing application impact requires additional evidence.

## Technical evidence

The [local application case study](docs/case-studies/anythingllm-local-2026-11-06/README.md) documents a bounded test of AnythingLLM and Qwen3, with configuration and evidence limitations. The [experimental AgentDojo case study](docs/case-studies/agentdojo-local-2026-11-25/README.md) records a local tool-use benchmark with simulated tools.

## Try it locally

On Windows, run [start-customer-preview.cmd](start-customer-preview.cmd) and open [the local preview](http://127.0.0.1:8000/). **Demo** opens the fictional document-assistant walkthrough and the broader illustrative report without a provider key.

See the [demo guide](docs/pilot-demo.md), [customer access setup](docs/customer-access.md) and [application API setup](docs/application-api.md). The [security and deployment notes](docs/security-pilot.md) describe the hosted pilot entry point and release boundaries.

To render and independently check an existing garak scan export:

    python generate_report.py path/to/garak.RUNID.report.jsonl --target "your model"
    python audit_report.py path/to/garak.RUNID.report.jsonl

## Roadmap

- **Pilot with design partners.** Validate the assessment and remediation workflow on authorised staging applications, broaden provider coverage and improve evidence collection.
- **AI remediation agent.** Given explicit repository and staging access, propose a targeted fix on an isolated branch. Replay the original test and normal-use controls, then present the code change and retest evidence for authorised review before any merge or deployment. The current preview provides repair guidance and a fictional fix-and-retest walkthrough.
