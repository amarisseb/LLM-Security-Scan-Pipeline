# Arisec application assurance: implementation decision

Research checked on 23 November 2026. This is a technical integration plan,
not a claim of unique market positioning or completed integrations.

## Destination

An authorised staging assessment should connect attacker-controlled content to
an observed application action, explain the permission boundary involved, and
replay the case after a fix. Test legitimate task completion independently of
attack success. A model that refuses everything must not look like a successful
product. A missing trace must not become a green result.

Example: an instruction planted in a retrieved document causes an agent to
read another test tenant's synthetic document and send it to a controlled mock
mailbox. Record each boundary: retrieval, model/tool decision, permission check,
document read, delivery receipt. A tool call alone is an attempted action;
successful delivery requires an independently observed receipt. A retrieved
document read does not itself establish disclosure to an external recipient.

## Open-source components and decisions

| Project | Verified role | Incorporation decision | Boundary |
| --- | --- | --- | --- |
| [PyRIT](https://github.com/microsoft/PyRIT) | Adaptive multi-turn AI red teaming; extensible Python components. [MIT](https://github.com/microsoft/PyRIT/blob/main/LICENSE). | First additional attack-engine candidate. Run in an isolated, version-pinned worker behind an Arisec target adapter and budget. | An attacker model/scorer is not an independent application-state observer. Provider use can cost money. Do not let its provider clients bypass Arisec's target controls. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Dynamic prompt-injection environments; user-task utility and injection-goal checks can inspect before/after state and tool traces. [MIT](https://github.com/ethz-spylab/agentdojo/blob/main/LICENSE). | Reference benchmark for testing the outcome evaluator and an optional benchmark worker. | Its own environments are not automatically a customer's application. Its README warns of API changes. Preserve benchmark version and original results. |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | Tool-using, multi-turn evaluations and extensible scorers; Docker sandbox support. [MIT](https://github.com/UKGovernmentBEIS/inspect_ai/blob/main/LICENSE). | Evaluation-runner candidate for reproducible agent labs, rather than adding a second scheduler immediately. | Only operations explicitly performed through the sandbox API execute there; evaluation Python itself does not automatically move into a container. |
| [OpenTelemetry Python](https://github.com/open-telemetry/opentelemetry-python) and [Collector](https://github.com/open-telemetry/opentelemetry-collector-contrib) | Application tracing and telemetry processing. Python SDK is Apache-2.0. | Basis for an opt-in customer-side observer and trace correlation. | Spans are evidence inputs, not proof by themselves. Require trustworthy tool-side receipts, coverage, per-run binding and redaction. |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) | Official MCP client/server protocol SDK. [MIT](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE). | Add tool inventory and dedicated mock-tool tests for authorised customer environments. | Tool schemas describe capabilities; they do not prove exploitable behaviour. Never execute uploaded stdio configuration on the web server. |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | Application evaluations, CI integration, adaptive single/multi-turn strategies, indirect injection and regression strategies. [MIT core](https://github.com/promptfoo/promptfoo/blob/main/LICENSE). | Useful comparison engine and optional import/export adapter after the evidence format stabilises. | Substantial overlap: none of these features alone establishes an Arisec moat. Check strategy dependencies, external services and data movement. |
| [gVisor](https://github.com/gvisor/gvisor) | Application kernel providing a container/host isolation layer. [Licence](https://github.com/gvisor/gvisor/blob/master/LICENSE). | Linux execution boundary candidate for agent/tool labs. | Does not replace explicit network egress restrictions, filesystem isolation, resource limits or tenant separation. Not validated on this Windows workstation. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Agent/MCP/skill discovery and risk analysis. [Apache-2.0](https://github.com/snyk/agent-scan/blob/main/LICENSE). | Study/optional explicit customer integration; not a default private-data processing dependency. | README documents an external analysis API and experimental CLI output. Scanning configurations may start commands or contact remote servers. |

Do not install all frameworks in the FastAPI environment. Select one execution
path at each boundary. Keep attack-engine dependencies in pinned optional
worker images with explicit input/output formats. Verify transitive licences,
attribution, release compatibility, telemetry defaults and dependency integrity
for the exact chosen versions before incorporating their code. No upstream code
was copied and no new third-party package was installed during this research.

Other reviewed options: [Giskard OSS](https://github.com/Giskard-AI/giskard-oss)
provides additional agent/RAG evaluation coverage, but is not needed alongside
every other evaluation engine in the first slice. [LangGraph](https://github.com/langchain-ai/langgraph)
is a possible reference application framework, not an evidence verifier.

## Applications to test under our control

1. [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent):
   purpose-built educational ReAct-agent target, including cross-user transaction
   access. README describes Apache-2.0 and local Ollama support. Run a separately
   provisioned disposable instance with synthetic data, verify current dependency
   compatibility, and observe its tools/database. Do not represent its intentional
   weaknesses as newly discovered product vulnerabilities.
2. [LibreChat](https://github.com/LibreChat-AI/LibreChat): MIT application with agent,
   retrieval and MCP capabilities. Use an owned instance with two synthetic test
   users, isolated documents and mock integrations. A product feature is not a
   claim of vulnerability: test and report what actually happens.
3. [Dify](https://github.com/langgenius/dify): useful owned workflow/RAG test target,
   but its [licence](https://github.com/langgenius/dify/blob/main/LICENSE) contains
   additional multi-tenant and branding conditions. Do not use its code as a
   drop-in foundation for Arisec's SaaS.

[Flowise's current README](https://github.com/FlowiseAI/Flowise) says it has been
archived. Do not choose it as the primary new integration without considering
that lifecycle status. Open-source availability never authorises testing somebody
else's hosted installation; deploy our own target instances.

## Architecture and integration order

1. **Evidence contract and repeatable fixture (implemented).**
   `app/assurance.py` evaluates an exact, versioned actor/action/resource case
   against correlated local observer receipts. Reports verified test breach,
   not observed or inconclusive, plus independent legitimate-task completion.
   `tools/run_assurance_lab.py` exercises vulnerable, access-controlled and
   blanket-refusal implementations using in-memory synthetic documents.
   This is a deterministic access-control fixture: no actual LLM, prompt
   injection, AgentDojo or PyRIT execution, and no customer vulnerability claim.
   The existing garak JSONL format and public scan flow are unchanged.
2. **Real-model benchmark adapter (implemented as an optional local lab).**
   See [the AgentDojo lab](agentdojo-lab.md) for the bounded runner, isolated
   pinned environment, controls, provenance and commands. Real-run results must
   be checked independently of offline adapter tests.
   Pin an AgentDojo release and its benchmark version in a separate environment.
   Run a known task with a selected local or explicitly funded model. Translate
   original utility/security outcomes without inverting their meaning: in
   AgentDojo's injection task API, `security(...) == True` means the attack goal
   succeeded. Retain original logs and distinguish benchmark outcomes from
   customer-environment outcomes. Test version drift against captured fixtures.
3. **Adaptive attack worker.**
   Pin PyRIT separately; implement its target bridge using Arisec's validated
   transport, including stateful conversation IDs where needed. Enforce turn,
   token, request, wall-time and cost budgets outside the attacker agent. Any
   detector or model judge contributes a candidate, never an invented receipt.
4. **Customer-side observer and staging adapter.**
   Opt-in outbound connector with narrowly scoped project credentials; no public
   arbitrary-code runner. Map actual tool/database operations to receipts and
   derive the authenticated actor from the session, not model tool arguments.
   Specify which actions and time window are fully observable. Authenticate
   events, reject replay, bind tenant/project/run, minimise sensitive content,
   and isolate the observer from the attacker's writable environment. Generic
   OpenTelemetry cannot establish those trust properties automatically.
5. **Indirect injection and tool-chain tests.**
   Inject synthetic text only into explicitly permitted document/tool-response
   locations. Track provenance; snapshot state; use mock mail/webhooks/payment
   tools. Confirm specific outcomes from state or delivery receipts. Restore
   the environment between cases. Execute in disposable restricted workers,
   with deny-by-default egress independent of URL string validation.
6. **Replay and useful remediation.**
   Persist the authorised scenario, dataset/policy version, target build,
   engine/model versions, conversation and evidence references. Re-run on a
   fresh equivalent snapshot; show whether the failure reproduces and whether
   legitimate tasks still work. Repeated stochastic runs need uncertainty and
   denominators, not a single 'secure' percentage. Compare to benign controls.
7. **Longer-term research.**
   Evidence-backed attack-path graph; taint/provenance through retrieval and
   tools; minimisation of reproducible attack sequences; cross-agent delegation
   and identity-boundary tests; automated selection of regression cases under
   a cost budget. Proposed capabilities, not delivered features.

No link-only scanner can reliably infer private permissions, hidden tools or
internal document access. Keep onboarding simple, but distinguish black-box
endpoint coverage from connected staging coverage. Surface unavailable evidence
as unassessed/inconclusive rather than filling the gap with confident language.

## Local fixture

From the repository root:

```powershell
.\.venv\Scripts\python.exe tools/run_assurance_lab.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_assurance.py -v
```

The lab prints JSON; it does not start a server, request credentials, call a
provider, write customer records or produce a garak report. It proves that the
local evidence evaluator separates committed reads from denied attempts and
distinguishes a useful permission fix from blocking every task. It does not
validate a real AI system or remote collector authentication.

## Primary technical references

- [PyRIT framework](https://microsoft.github.io/PyRIT/latest/code/framework/).
- [AgentDojo outcome API](https://github.com/ethz-spylab/agentdojo/blob/main/src/agentdojo/base_tasks.py).
- [Inspect sandbox execution boundary](https://inspect.aisi.org.uk/sandboxing.html).
- [Promptfoo strategies](https://www.promptfoo.dev/docs/red-team/strategies/).
- [Collector redaction processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/redactionprocessor).
- [Agent Scan data flow](https://github.com/snyk/agent-scan#how-it-works).

Sources establish documented capabilities and licence text at the checked date;
they do not establish customer demand, Arisec integration compatibility or a
guarantee that any particular deployment is secure.
