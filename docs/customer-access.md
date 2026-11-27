# Customer access

The customer interface offers **Demo**, **What we test**, **Test your AI**, and
**Plans**. The example endpoint uses an in-process scripted adapter; its scan
does not fetch a URL or call a provider. Reports show red/green percentages for
potential attack success and apparent resistance, with categories not assessed
kept separate. These are sampled observations, not a
percentage of a company's systems that are vulnerable or a compliance certificate.

## One free scan

`app.pilot:app` enables `ARISEC_SELF_SERVE=1` by default. The API issues a random
guest session in an HttpOnly, SameSite=Lax cookie. One free **prompt-injection
category** scan is reserved atomically in SQLite, for both the account and its
network. The other categories are not included. Failed scans restore
the allowance. Shared networks can share an allowance; this is an abuse control,
not a billing system. Clearing cookies does not create another network allowance.

Signup promotes the guest identity, retaining access to that guest's reports.
Passwords use salted PBKDF2-SHA256 and sessions are stored as hashes. Signup does
not reset the free allowance or unlock full scans. Existing hourly/daily limits
still apply. There is no automated payment integration, email verification,
password recovery or cross-device guest report recovery yet.
Do not imply that an account email has been verified.

## Consultation-based assessments

Full and Bespoke assessments are **quoted after consultation**. The account's
consultation form saves a private request for operator review, at most once per
day per account. It does not send an email or take payment. Operators can list
requests with `python tools/manage_consultations.py --db PATH_TO_ACCOUNTS_DB`.
Do not expose that output or database: it contains contact details and messages.

Full scan access is enforced on the server through an active, expiring
subscription grant. The operator grants it after agreeing scope and commercial
terms; selecting a card, signing up or submitting a consultation does not grant
access. `app.billing.grant_subscription(principal_id, 'full', expiry_unix_seconds)`
is a server-side/operator API, never a customer-facing HTTP endpoint.

Full currently includes the five configured families: prompt injection,
jailbreaks, encoding, unsafe-response checks and synthetic prompt-disclosure
checks where the connector supports them. It does not mean all garak probes or
all possible security risks. Additional compatible probes require agreed scope
and implementation/validation; Bespoke is a consultation-led service.

## Connecting a feature

The form accepts either an HTTPS JSON endpoint or a supported provider's model
name. A model scan needs the customer's API key and consumes their provider
quota. It tests the model baseline; it does not include their deployed application
instructions, retrieval, permissions or tools.

An application endpoint must first prove control through a short-lived file at
`/.well-known/arisec-verification.txt` on the same origin. Arisec fetches that
single file over validated, pinned HTTPS without redirects or credentials. This
requires help from whoever maintains the target if the customer cannot publish
the file themselves. An authorisation checkbox alone does not grant target access.
Non-standard JSON APIs may also need request/response mapping from a developer.
Production browser scanning remains disabled.

## Working example endpoint

Run `start-customer-preview.cmd` and choose **Test your AI → Use example endpoint**.
The default address is `http://127.0.0.1:8000/demo/endpoint` (the port follows your
preview). It accepts `POST` JSON `{"message":"Hello"}` and returns an `answer`
field. No provider key is needed. Review the authorisation statement, start the
scan and use the report's action plans. The example does not use the guest's free
scan allowance; it still has normal rate limits and queue limits.

Example runs have no free-trial or hourly/daily assessment allowance. Basic
request throttling and queue bounds still protect the service. The one-free-scan
restriction applies to customers' own AI, including after signup.

The public report preview is intentionally compact. Only a short prompt-injection
recommendation is public; registration unlocks general example remediation guides
for other categories. These are educational guides, not findings about the
customer's AI. Full testing still requires agreed assessment access. The API
redacts locked plans as well as the UI, and signup does not grant paid scan access.

This is a scripted assistant, not a real LLM. Its short scan samples one prompt
per probe and generates a standard report through the real scan engine. Only the
exact configured example endpoint is recognised. On a public deployment, set
`ARISEC_PUBLIC_ORIGIN=https://YOUR_DOMAIN` and `ARISEC_LOCAL_PREVIEW=0`. The UI
then supplies `https://YOUR_DOMAIN/demo/endpoint`. That example runs in-process
without outbound HTTP or DNS. Real targets retain private-address blocking and
ownership verification. Host the public app with HTTPS and trusted proxy settings.

Reports include an owner, specific actions, completion checks and a retest plan.
Related OWASP mitigation and NIST risk-management references are guidance, not
evidence that an application satisfies a standard or certification.

## Operation

Set `ARISEC_ACCOUNTS_DB` to private durable storage (default
`.arisec-private/accounts.sqlite3`), protect and back it up, and serve behind HTTPS
with one API worker. Account, verification and scan mutations enforce same-origin
requests. Do not expose the local demo launcher publicly.

An isolated HTTP preview may set `ARISEC_LOCAL_PREVIEW=1`, with loopback-only
binding. This only permits a local non-Secure cookie: authentication, quotas and
target checks still apply. Never set it on a public deployment. Set isolated
`SCAN_OUTPUT_DIR` and `ATTESTATION_LOG_PATH` when testing; normal startup performs
retention cleanup in its configured scan directory.

The older bearer-invite mode remains available with `ARISEC_SELF_SERVE=0` and an
operator-owned `ARISEC_ACCOUNTS_FILE`; see [the legacy pilot guide](security-pilot.md).
The current interface is intended for session access. This is local source code,
not evidence of a publicly deployed or independently audited service. Legal
review of the attestation and deployment security review remain release work.
