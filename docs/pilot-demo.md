# Running Arisec and collecting a first case study

## Start the local UI on Windows

From the repository directory, run `./start-demo.cmd` in PowerShell, or double-click
`start-demo.cmd`. It creates `.venv` if needed, installs missing dependencies and
Chromium, and runs the API, UI and demonstration chatbot.

Open http://127.0.0.1:8000/ and keep the terminal open. If the terminal closes,
the server stops and the browser reports `ERR_CONNECTION_REFUSED`. Start the
command again to restore it. The server also stops when the computer shuts down.

Select **Web page**, choose **use the demo chatbot**, review the statement,
and start a scan. Runtime varies; allow several minutes. This bot has scripted
responses: label screenshots from it as a demonstration, not independent evidence
of real-model security testing. `sample_report.html` also uses illustrative data.

The launcher is a development setup with relaxed rate limits. It is not the
deployment entry point for public customers.

## First independent target

Run a copy you control instead of scanning a project's public service.

- [AI Goat](https://github.com/dhammon/ai-goat) uses a real local Vicuna model and
  provides deliberately vulnerable challenges. Its README describes an approximately
  8 GB model download and Docker setup. First confirm the chosen challenge offers
  a text input/reply UI Arisec can drive; compatibility has not been established here.
- [OWASP DonkAI](https://owasp.org/projects/donkai) is a deterministic, rule-based
  lab, without a real LLM. Useful for integration demonstrations, but do not present
  its responses as real-model findings.

Docker Desktop must be running before either Docker-based setup can start.
Do not publish a deliberately vulnerable lab through a public tunnel. Arisec's
production URL checks block local targets. The demo runner supports exact local
application API endpoints through [the local-lab connection](local-lab.md).
Its browser mode still only permits the built-in demo bot on loopback. Do not
disable URL validation globally.

## Evidence to retain

For each real lab run, record the repository and commit, challenge, actual model
and version, configuration, date, probe cap and scan ID. Keep the raw garak
report and hit log from `garak_runs/<scan_id>/`, alongside the exact prompt and
response for a finding. Review it manually: detector matches are candidate findings.

Change one relevant defense, repeat with the same probes, and show the before and
after. Failed or unanswered tests must remain visible. Describe the percentage
as the share of evaluated attack attempts detected as successful, not the share
of the application that is insecure.

## Public pilot boundary

The existing browser egress gaps need network isolation before a public
self-service deployment. Provider keys now use explicit runtime credentials and
fixed provider endpoints; compatibility is covered with stubbed HTTP transports,
not paid live scans of every provider. Request-phase timeouts and cooperative scan
budgets are not a hard process deadline for the provider path.
Local reports are accessed by possession of their scan link; there are no user
accounts. The authorization statement still needs legal review.

An accurate early-interest post can say:

> I'm building Arisec, a tool that runs automated adversarial tests against AI
> interfaces and model APIs, then shows the prompts, responses and suggested fixes.
> I'm preparing a reproducible case study on a self-hosted lab and looking for a
> few teams interested in an authorized pilot. What would make this report useful
> to your team?

Only describe the lab case study as completed once the real run is documented.
