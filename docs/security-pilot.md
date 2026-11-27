# Hosted pilot security boundary

This document describes legacy operator-managed access with
`ARISEC_SELF_SERVE=0`. The current customer entry point defaults to cookie-based
self-service; see [customer access](customer-access.md) for that flow. The
transport, worker and report limitations below still apply.

This hardening supports an invite-only, operator-supervised API pilot. It is
not an independent security audit or a claim that arbitrary browser execution
has been made safe. Production browser scans are rejected before DNS. The
Playwright path remains available only through the explicit loopback demo launcher.
Do not expose that launcher through a tunnel or public reverse proxy.

## Enforced in code

- Every scan start, status read and report read requires a bearer invite and HTTPS.
- Accounts are operator provisioned. Only a SHA-256 token digest is stored.
  Scan identity and attestation email come from that account, not the submitted email.
- Report reads check the account ID; knowing a scan URL is insufficient.
  Old reports without an owner remain inaccessible in production.
- Web/application targets require an exact operator-approved origin before DNS.
  Approval is offline and manual; there is no self-grant API or ownership checkbox bypass.
- All scanner requests are throttled before parsing/DNS; bodies have a 128 KiB
  limit and an absolute read deadline. URL lookups have bounded caller waits
  and a bounded number of resolver threads.
- Four running/queued reservations are allowed by default. Each admitted scan
  runs in a fresh child process with credentials passed through a private pipe,
  a restricted inherited environment and a hard time budget. The parent kills
  the worker process tree at timeout. This is process separation, not an OS sandbox.
  On Windows, the worker is assigned to a kill-on-close Job Object before its
  stdin job is sent; cleanup waits for the job's active process count to reach
  zero. On POSIX the worker has its own process group. These mechanisms do not
  themselves restrict filesystem or network access.
- The application connector pins its validated address, verifies the original
  TLS hostname, refuses redirects and bounds response size and elapsed request time.
- Prompt-leak checks on web/application paths show “not verified”; their synthetic
  system prompt is not installed on the remote application. Raw detector match
  totals remain available and are explicitly not confirmed security impact.

## Provision a pilot

First agree scope and verify control of the exact target through a DNS TXT or
HTTPS challenge. Record what was checked and who approved security testing.
The provisioning tool records the operator's evidence; it does not perform the
challenge or claim automatic verification.

```powershell
.\.venv\Scripts\python.exe tools\manage_pilot.py --id pilot-001 --email builder@example.com --origin https://staging.example.com --control-evidence "Agreed endpoint /api/ai; DNS challenge verified by operator; approval reference PILOT-001"
$env:ARISEC_ACCOUNTS_FILE = (Resolve-Path .arisec-private\accounts.json).Path
```

The token is shown once. Deliver it privately; never put it in a link, source
control, analytics or a target request template. It is an Arisec credential,
separate from the customer's temporary application/provider credential. Reissue
the same account ID to rotate the invite. Remove the account entry to revoke it;
the file is reread on each request. Revocation blocks new requests, not jobs already
running. To stop an active pilot immediately, stop its scan worker/service too.
Do not reuse an account ID for a different customer.

## Deployment checks still required

Run the production API with one worker, as a dedicated unprivileged service
account, behind HTTPS. The development launcher binds loopback and is not the
production entry point. Set `ARISEC_LOCAL_DEMO=0` and use the production ASGI
application `app.pilot:app`. This serves the supplied UI with a hash-based script
Content Security Policy and system fonts, checks account configuration at startup,
and refuses to start with the demo bypass enabled. Do not use `demo/run_demo.py`
to serve public traffic.

After configuring the real TLS proxy and the account file, a single backend can
be started with:

```powershell
$env:ARISEC_LOCAL_DEMO = "0"
.\.venv\Scripts\python.exe -m uvicorn app.pilot:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips 127.0.0.1
```

The public HTTPS proxy must replace, rather than trust a visitor's values for,
`X-Forwarded-For` and `X-Forwarded-Proto`. This example assumes that proxy is on
loopback. Do not copy its trusted address setting to a different architecture.
Without the TLS proxy, the scan API intentionally rejects plain HTTP requests;
opening port 8000 to the internet is not an alternative.

Trust forwarded scheme/client headers only from the actual TLS proxy. Restrict
direct access to the backend; never use `--forwarded-allow-ips='*'` on a public
listener. Middleware does not interpret caller-supplied forwarded headers.
Configure shared edge request limits before adding workers or replicas; current
in-process limits and queue capacity are per API process, not distributed.

Set host/network egress rules independently to deny private, metadata and internal
networks. Test these on the actual hosting environment; no host firewall, VPC or
container policy is installed by these repository changes. Keep browser scanning
disabled until there is a separately verified restricted browser worker network.

Restrict the accounts file, verification evidence, attestations, report directories
and backups to the service/operator accounts. They must not be static web content.
The default seven-day scan cleanup is not a promise to erase backups or separately
copied case studies. Agree retention and deletion with each pilot. Stored reports
may contain sensitive responses; automatic API-key redaction is not a complete
data-loss prevention system. Use synthetic data and restricted temporary keys.

Pin and review dependencies, run a vulnerability audit in the target environment,
and keep Chromium current if using the local demo. The root requirements pin the
direct versions tested here; they are not a complete transitive lock or a clean
vulnerability-audit result. Have the draft authorisation/privacy wording reviewed
before onboarding external users. Arrange an independent review before public SaaS.

## Operator settings

`ARISEC_MAX_PENDING_SCANS` defaults to 4 including the running job.
`ARISEC_SCAN_TIMEOUT_SECONDS` defaults to 600 (clamped to 30–1800).
`ARISEC_PROMPT_CAP` defaults to 10 per probe (clamped to 1–100).
No request can choose these settings or enable local exceptions.

The invite file is a pilot mechanism, not a full account product. Password reset,
MFA, billing, team roles, a distributed queue and account lifecycle are separate
SaaS work. Do not advertise these as implemented.
