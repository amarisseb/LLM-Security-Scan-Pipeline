# Local-lab connection

The production application blocks private and loopback destinations. The local
demo launcher can explicitly register exact application endpoints in its process.
There is no request flag or environment variable that enables this exception.

The customer preview can also use an operator-registered exact lab endpoint.
Registration must happen in the local launch process after importing the app;
it is not accepted from a browser request. The target permission exception
requires a verified loopback preview request and an explicit same-origin Origin.
The UI reads the registered addresses from local `/demo-config`, fills the
AnythingLLM request/response settings and omits the public verification-file
step for those exact addresses. Application API keys and scan attestation are
still required where applicable. Other targets keep the normal ownership checks.

For example, after creating an AnythingLLM workspace with slug `arisec-lab`, run:

```powershell
.\start-demo.cmd --lab-target http://127.0.0.1:3001/api/v1/workspace/arisec-lab/chat
```

Stop an existing Arisec demo before starting another on the same port. In the UI,
choose **Application endpoint**, then select the configured local endpoint. The
AnythingLLM preset fills in:

```json
{"message": "{{prompt}}", "mode": "chat"}
```

The response text path is `textResponse`. Supply an AnythingLLM API token in the
bearer-token field. Configure the workspace to avoid conversation-history carryover
between attacks. Use synthetic documents and a dedicated workspace.

Only the full registered URL is permitted. Another path or port on the same host
remains blocked. Numeric addresses `127.0.0.1` and `[::1]` are supported; hostname
aliases, metadata endpoints, URL credentials, query strings and redirects are not.
Requests are pinned to the numeric loopback address without DNS. Local exceptions
are only accepted from a loopback client and the demo server binds to `127.0.0.1`.
Do not deploy the local demo launcher as a public service.

The `--cap` option also controls prompts per probe for registered local application
targets. Start small, for example `--cap 1`. This is one prompt per probe class,
not one prompt for the entire category. Results still require human review.

## Docker startup issue encountered during setup

Docker is optional for this workflow. AnythingLLM Desktop includes its own local
model engine and developer API, so it can provide a real application target
without Docker Desktop. Use the official Windows installer from
https://anythingllm.com/download and allow its bundled backend to finish unpacking
before launching it. The installer and subsequent model downloads are separate
steps; installing the application does not mean a model is ready.

For a local Arisec lab, leave AnythingLLM's **Enable network discovery** setting
off. Its default loopback listener is sufficient for a scanner on the same
computer. Create a dedicated workspace, use synthetic data and a small local
model, then check a normal chat response before starting a scan. Confirm the
actual API port and workspace slug before registering the exact chat endpoint
with `--lab-target`; the URL above is an example, not a discovered connection.

References:
- https://docs.anythingllm.com/installation-desktop/windows
- https://docs.anythingllm.com/installation-desktop/overview
- https://docs.anythingllm.com/setup/llm-configuration/local/built-in

Docker Desktop 4.67.0 failed before starting its engine. First it reported an
inaccessible `Docker/run/dockerInference` socket, then a
`docker-secrets-engine/engine.sock` socket. The first runtime directory was
preserved as a timestamped `run.arisec-backup-*` folder. No persistent Docker
images, containers or volumes were deleted. A second runtime-folder repair was
not approved and was not performed.

Save work and use **Start > Power > Restart**, then open Docker Desktop. A full
Restart may release inaccessible sockets that survive closing the application.
If the failure remains, check the current Docker Desktop release and its
troubleshooting guidance before attempting another repair. Do not factory-reset
Docker or unregister its WSL distributions merely to clear a runtime socket.

Related reports (not proof of the exact cause on this machine):
- https://github.com/docker/desktop-feedback/issues/460
- https://github.com/docker/desktop-feedback/issues/625
- https://docs.docker.com/desktop/troubleshoot/overview/

AnythingLLM Desktop was installed on 6 November 2026 using the official installer.
Its Authenticode signature was valid and identified Mintplex Labs Inc. Installation
completed with exit code 0; the bundled Lemonade and llama.cpp engines installed
successfully. The application API answered `GET /api/ping` on `127.0.0.1:3001`.

The initial loading-screen failure was traced to an inherited `RUST_LOG=warn`
environment variable. Prisma 5.3.1's binary client waits for an INFO-level startup
message from its query engine. The filter hides that message, so the engine can
answer direct queries while the application waits indefinitely. An isolated
read-only Prisma query timed out with the filter and succeeded immediately when
it was removed. After restarting AnythingLLM without that variable, both
`/api/ping` and the previously stalled `/api/onboarding` responded normally.

Use `start-local-lab.cmd` to launch AnythingLLM from this repo. It clears
`RUST_LOG` only inside its local environment and the launched process; it does
not change Windows user or system settings. Fully exit an already stuck
AnythingLLM instance first, as launching a second instance may hand control back
to the existing process. This fixes application startup; downloading a language
model and creating the test workspace remain separate setup steps.

All 18 focused policy, local transport and application API tests passed in the QA
review. A real-model scan subsequently completed on 6 November 2026 using a
dedicated AnythingLLM workspace and Qwen3 0.6B. See the saved
[case study](case-studies/anythingllm-local-2026-11-06/README.md).
Transport tests and the scripted demo bot remain separate from that evidence.
