# Arisec engineering and security standard

Arisec's customer goal is to make finding, understanding, repairing and verifying
AI security weaknesses accessible without a dedicated cyber team. Specialist
engineering remains behind the interface. Product claims must match implemented
coverage and actual evidence.

## Required boundaries and evidence

| Area | Required behaviour | Current verification / remaining work |
| --- | --- | --- |
| Customer isolation | Server-derived identity, owner-scoped reports, no plan self-grants, CSRF protection | Account, billing, security-boundary and assessment API regressions |
| Target access | Authorised scope before tests, validated/pinned destinations, TLS hostname checks, no redirect credential forwarding | Application connector and target-verification tests; browser hosting remains disabled |
| Secrets | No credentials in URLs, reports, source control or inherited worker environments | Provider credential, application mapping and worker IPC regressions |
| Execution | Bounded requests, bytes, time, queues and tools; confirmed process-tree cleanup before admission release | Deadline, worker containment and assessment lifecycle tests; process separation is not a complete OS/network sandbox |
| Finding quality | Original evidence, explicit scope, benign controls, truthful inconclusive states | Report, remediation, profile and AgentDojo integration tests; detector matches are not automatically confirmed impact |
| Customer experience | Plain-English impact/actions, accurate coverage, clear navigation, unavailable capabilities labelled | Isolated browser journey; example's five-category scope distinct from the one-category customer trial |
| Dependencies | Tested versions, reviewed licences/data flows, isolated engine dependencies | Top-level app pins, optional AgentDojo snapshot and immutable CI action refs; complete transitive hash locks/advisory review remain release work |
| Deployment | Validated image, HTTPS, restrictive egress, backups/recovery, monitoring and private data handling | Deployment preparation exists; a hosted image/runtime and operational readiness have not been established |

## Future repair-agent contract

The customer-facing Find & fix demonstration (`/demo/repair-example`) executes
trusted before/after permission-check functions over fresh synthetic records.
It shows a cross-organisation disclosure, a prewritten code correction, a replay
of the denied request and a legitimate-access control. It makes no network calls,
executes no submitted/generated code and changes no customer system. Its prompt
and tool request illustrate the scenario; no live model chooses that tool call.
The calendar benchmark is retained only in the explicit `?lab=1` development view;
its server-side local-execution restrictions continue to apply.

The customer workspace uses Overview, My checks and Account. Connections progress
through target, access and review steps. Credentials/attestation are cleared on
target changes; logout also clears ownership instructions and connection state.
Saved-check summaries are owner-scoped and capped at 20. The pilot's status-file
lookup remains linear; an indexed history store is required before higher volume.

This capability is not implemented by the current calendar laboratory or by
remediation text. Before it can be offered to customers:

1. Obtain scoped code/staging access and bind the request to the verified owner,
   repository, revision, target and finding. An endpoint/API key is not code access.
2. Prepare a change on an isolated branch/worktree. Repository instructions and
   model output are untrusted data, not permission to run commands or access secrets.
3. Test without production credentials. Separate the attack worker from the code
   writer and from deployment authority; neither can grant itself more access.
4. Show a reviewable diff, why it addresses the finding, test results and limits.
5. Replay the failing attack and normal-use controls on a fresh staging build.
   Save the evidence; report partial/inconclusive outcomes honestly.
6. Obtain authorised approval for merge/deployment. Record the approved revision
   and a rollback path. Do not change production automatically because a model
   says its patch is safe.

Examples of meaningful fixes include server-side record permissions, tool-call
authorisation, validated outputs and reduced tool privileges. A prompt wording
change alone cannot establish those controls.

## Development checks

`python tools/check_backend.py` removes inherited credential environment variables and runs backend
regressions against temporary isolated storage. `python tools/qa_assessments_ui.py`
checks the customer journey with a fixture and no provider/model calls. The
optional `--real-local-test` run is separate from routine CI and requires prepared
CPU assets. Do not use production databases or historical evidence folders in QA.
The runner retains the user's home/profile directories and executable search path;
it is not a sandbox against libraries discovering credentials or configuration on disk.
Current CI jobs cover Windows/Python 3.12; Linux/container execution still needs verification.

`.github/workflows/backend-checks.yml` defines backend and browser jobs with
read-only repository permissions, immutable action commits, no persisted checkout
credentials and no privileged `pull_request_target` execution. Adding the file
does not mean GitHub has run it or branch-protection rules are enabled.

## Reference frameworks

- [OWASP ASVS](https://asvs.owasp.org/) supplies application-security requirements.
- [OWASP GenAI risks](https://genai.owasp.org/llm-top-10/) informs AI threat coverage.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) informs risk-management process.
- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)
  informs least-privilege CI and handling untrusted code.

These are engineering references, not certifications or an assertion that every
requirement/risk is covered. Claims of compliance or independently verified
security require their own evidence and assessment.
