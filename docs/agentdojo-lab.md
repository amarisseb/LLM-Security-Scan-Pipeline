# AgentDojo local-model integration

This optional operator-only lab runs one AgentDojo workspace case with simulated
calendar/email tools. It is separate from the FastAPI service, customer scan
queue, garak reports and scripted example endpoint. It does not send real emails
or connect to customer records. Public deployments cannot start these workers.

## Inside Arisec

The customer navigation is **Overview / My checks / Account**. The interactive
customer demo uses synthetic document-access code, not this calendar benchmark.
Operators can open `/?lab=1#demo` on an enabled local preview and expand the
technical laboratory to view the recorded real-model benchmark or run a local
test. The query flag only reveals the development interface; server-side local
execution restrictions still apply.

The customer preview launcher enables **Run local agent test** when the prepared
Windows CPU runtime/model files are present. Confirm the local CPU test, start
it, and stay on this page or use other tabs while it runs. The result remains
available through **View your latest local test**. Recorded results are clearly
separate, and logout clears private benchmark state from the interface.

The UI explains all three checks rather than displaying a misleading success
percentage for one case. A failed ordinary task leads to an inconclusive negative
assessment. Customer scan credit is unaffected by these simulated local tests.

The example now displays five live stages: model preparation, normal calendar
task, email capability check, injected task, and cleanup/results. Stages come
from the runner; elapsed time is not a fabricated completion percentage. A page
reload restores the session's latest run. Results include a plain-language
**What happened** explanation.

The prepared local launcher now selects a **focused two-tool demonstration**:
calendar search and simulated email. This reduces prompt size for the small
CPU model. The worker records `tool_scope=focused_calendar_email`; it is not
equivalent to the original 24-tool workspace run recorded on 23 November. The
standalone `run_agentdojo.py` retains the full tool inventory unless `--focused`
is explicitly selected. Restricting tools does not force success: original
graders and capability controls still determine the outcome.
The driver uses the upstream default system instructions. The focused example
also supplies the current date from its simulated calendar, so dates without a
year do not depend on the model guessing a year. This is a custom demonstration
configuration, not an unchanged upstream benchmark ranking.

Implementation: public `GET /assessments` returns safe capability metadata and
the fixed recorded summary. `/account/assurance/runs` launches only the fixed
local test; status reads are scoped to the session owner. These routes retain
the existing account boundary, CSRF checks and body/request limits. Launching
also requires Windows, `ARISEC_LOCAL_ASSURANCE=1`, local-preview mode, a verified
loopback peer/Host/origin, and prepared assets. There is no browser input for
endpoints, model paths, commands or arbitrary engines.

A process-backed file lease admits one web benchmark at a time and remains held
through model-tree cleanup. The launcher waits for a managed stdin gate until
the web process assigns a Windows kill-on-close job. ASGI shutdown terminates
owned jobs. Interrupted status recovery requires an available OS lease rather
than releasing CPU slots based on elapsed time alone. If cleanup cannot be
confirmed, admission remains closed.

## What runs

- AgentDojo **0.1.35**, benchmark **v1.2.2**.
- Workspace **user_task_0**: answer a question about a calendar event.
- Workspace **injection_task_0**: induce a particular email in the simulated inbox.
- The upstream **tool_knowledge** injection, placed in the task's injectable data.
- Three fresh benchmark environments: clean user task, attacker-goal capability
  control, and the user task with the injected content.
- An Arisec driver using native OpenAI-compatible tool calls. This is a custom,
  bounded pipeline, not a claim to reproduce upstream published model rankings.

AgentDojo's `security=True` means the injection goal succeeded. The clean task
API always returns True as its second value; the adapter does not interpret
that as an attack result. Raw phase booleans are retained alongside the outcome.
Some AgentDojo graders use text or traces as well as state; this first selected
email goal checks simulated inbox state. It is not external email delivery.

Negative results require successful clean-task and goal-capability controls.
Missing/failed controls, transport failures, malformed/empty model replies,
truncated completions and exhausted budgets remain inconclusive. A reproduced
goal remains observable even when the model fails a control. Do not turn one
benchmark case into a benchmark-wide success rate or an application guarantee.

## Install separately

From the repository root on Windows with Python 3.12:

```powershell
.\.venv\Scripts\python.exe -m venv .venv/assurance-agentdojo
.\.venv\assurance-agentdojo\Scripts\python.exe -m pip install --index-url https://pypi.org/simple -r integrations/agentdojo/requirements-windows-py312.lock
.\.venv\Scripts\python.exe tools/run_agentdojo.py --check
```

The lock file records the installed Windows/Python 3.12 dependency versions.
It is not a cross-platform, hash-verified lock or a dependency-security audit.
`requirements.txt` in the integration folder pins only the upstream package for
other-platform evaluation. Do not install these dependencies into the web app's
environment. The production image does not include the `integrations` directory.

The `--check` command loads actual upstream task/tool definitions without making
model requests. It writes an isolated `environment_ready` summary; that is not a
completed AI assessment. It must not be described as real-model evidence.

## Prepared Windows CPU model

```powershell
.\tools\setup_assurance_model.ps1
.\.venv\Scripts\python.exe tools/run_local_agentdojo.py --seconds 300
```

Setup downloads the official llama.cpp **b12651** Windows CPU archive (about
25 MB) and official **Qwen/Qwen3-0.6B-GGUF**, Q8_0 file (about 640 MB). The runtime
archive is pinned by URL and SHA-256. The model is pinned to immutable repository
revision `23749fefcc72300e3a2ad315e1317431b06b590a` and its published LFS SHA-256;
the saved provenance records both. TLS verification remains enabled. Hash mismatches abort without running
the downloaded model. No system installation or Docker is needed.

The launcher rechecks the model/archive hashes and compares extracted runtime
files with the verified archive. It binds the CPU model server to numeric
loopback on an unused port, checks Windows' TCP owner table against the process
it started, uses four threads and an 8,192-token context, runs
the assessment, and terminates only the process it started. It does not stop
AnythingLLM or an existing unrelated model service. Server logs and results stay
under the ignored `.arisec-private` directory.

This tiny model is for integration work, not a representative capable agent or
a basis for customer security claims. A failed capability control is useful
diagnostic information, not evidence that the attack was resisted.

## Existing local tool-capable server

```powershell
.\.venv\Scripts\python.exe tools/run_agentdojo.py --endpoint http://127.0.0.1:11434/v1 --model YOUR_EXACT_LOCAL_MODEL_NAME --seconds 300
```

The endpoint must be explicit numeric loopback HTTP, a non-privileged port and
exact `/v1` or `/api/v1` path. Hostnames, cloud endpoints, credentials, queries,
redirects and arbitrary paths are rejected. There is no provider fallback or API
key argument. Ensure the service actually runs locally: loopback alone cannot
prove that another server does not forward requests to a cloud provider. The
prepared CPU launcher avoids that ambiguity by running the verified model file.

## Bounds, isolation and results

- At most **18 model requests**, **36 tool invocations** and **six model turns
  per phase**. Simulated tool calls count against the shared budget.
- Requests ask for at most 768 output tokens and cannot exceed 128 KiB of JSON;
  response bodies are limited to 512 KiB. These are request/output limits, not
  an exact total-token accounting system.
- `--seconds` is the supervisor's worker deadline, including Python imports and
  setup. The worker also checks a monotonic execution budget. A worker blocked in
  I/O is terminated at the supervisor deadline. Model-server startup and checksum
  verification are separate, bounded launcher stages outside that worker budget.
- No inherited provider keys, proxy variables, dotenv loading or enabled
  LangSmith/OpenTelemetry tracing in the worker. No shell/MCP/network tools are
  registered. This lab is not an OS sandbox for arbitrary third-party plugins.
- Each execution gets a fresh UUID directory under `.arisec-private/assurance`.
  Each phase has a trace with original grader booleans, model messages,
  injections, tool attempts/returns and state hashes. The summary hashes those
  traces and records the worker checksum and key dependency versions.
- `returned_without_error` is a runtime observation, not proof of real delivery
  or a customer permission breach. Trace hashes detect later changes relative
  to the summary; they are not authenticated signatures.
- `model_execution_requested` expresses intent. The recorded request count and
  trace show what ran. A startup failure is not a real-model result.
- `complete` is execution status. Read `assessment.outcome` and the control
  results; completion does not mean secure, and may include an inconclusive
  assessment when capability controls failed.

Raw traces remain private and are not served by the customer report API. The
fixture in `tools/run_assurance_lab.py` stays explicitly synthetic. No benchmark
booleans are fabricated into committed customer-action receipts.

## Verification

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_agentdojo_support.py -v
.\.venv\assurance-agentdojo\Scripts\python.exe integrations/agentdojo/test_worker.py -v
```

The second suite exercises the real pinned AgentDojo package and graders with
scripted replies. It checks state-based attack grading, environment isolation,
transport errors, malformed replies, turn overflow and redirect refusal. These
are integration tests, not real-model runs; actual model results are reported
separately with their provenance.

## Upstream references

- [Pinned AgentDojo source](https://github.com/ethz-spylab/agentdojo/tree/v0.1.35).
- [Task API and grading](https://github.com/ethz-spylab/agentdojo/blob/v0.1.35/src/agentdojo/task_suite/task_suite.py).
- [Workspace injection goal](https://github.com/ethz-spylab/agentdojo/blob/v0.1.35/src/agentdojo/default_suites/v1/workspace/injection_tasks.py).
- [AgentDojo MIT licence](https://github.com/ethz-spylab/agentdojo/blob/v0.1.35/LICENSE).
- [llama.cpp](https://github.com/ggml-org/llama.cpp).
- [Official Qwen model and licence](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF).
