# Arisec's initial product hypothesis

Arisec helps small product teams verify and fix weaknesses in the AI features
they ship. The proposed initial offer is an assisted assessment of one feature,
reviewed attack evidence, a practical fix discussion, and a documented retest.

This is a positioning hypothesis, not validated demand or a unique technical moat.
Promptfoo already supports browser, HTTP and model targets, application-specific
tests and CI. Giskard has agent scans and reviewed attempts. Mindgard sells
reproducible findings and retests. Avoid claiming those workflows are unique.

The testable advantage is delivery for a narrower customer: a small SaaS team
without a dedicated AI-security engineer. Measure whether Arisec can get their
real feature connected, remove false alarms and help ship a verified fix with
less customer work than their current process.

## Customer problems to validate

1. They don't know which part of an AI feature is exposed or how to connect a scanner.
2. Generic model results don't reflect their application's prompts and controls.
3. Security findings lack enough evidence to reproduce and prioritize them.
4. After a fix, they cannot tell whether the same attack still works.

## First five pilot conversations

Ask for the last actual security review, who did it, time spent, tools used,
what changed as a result, and who could authorize a paid follow-up. Ask to assess
one staging feature with defined boundaries. Do not use hypothetical praise as
validation. Stronger signals are access to a real test feature, an engineer
working on a finding, a retest request, and eventually payment.

After three to five pilots, decide whether the repeated value is setup,
human-reviewed assessments, regression testing, or reporting. Concentrate the
product there rather than trying to match every enterprise platform feature.

## Implementation boundary today

Available: web text interfaces, provider-model baselines, public HTTPS JSON
application APIs, component metadata, candidate evidence and JSON exports.

Still required for the broader workflow: authenticated project ownership, a
review/triage record, saved regression cases with exact replay, comparison runs,
customer policy assertions, and controlled private-network execution. Specialized
RAG, file and agent tests require dedicated adapters and checks.

## Primary references checked on 6 November 2026

- https://www.promptfoo.dev/docs/red-team/quickstart/
- https://docs.giskard.ai/hub/sdk/guides/scans
- https://mindgard.ai/services/ai-red-teaming

Vendor documentation establishes competing supply and described workflows. It
does not establish demand for Arisec or willingness to pay for this offer.
