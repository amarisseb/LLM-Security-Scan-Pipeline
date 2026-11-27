# Arisec engineering requirements

Arisec helps non-technical customers find, understand, repair and verify AI
security weaknesses. Customer language is British English. Keep the current
capabilities, experimental laboratories and future work clearly distinct.

## Security boundaries

- Authenticate and authorise every private read and mutation. Derive identity
  from server sessions, never submitted email, plan or owner fields. Preserve
  same-origin CSRF checks, body/time limits, tenant isolation and rate limits.
- Validate targets before network activity. Preserve address pinning, TLS
  hostname verification, redirect refusal and bounded responses. Never add a
  public flag that enables private-network or local-lab access.
- Keep provider/application keys out of URLs, logs, persistent browser storage,
  subprocess arguments, source control and inherited worker environments.
- Treat model text, retrieved content, repository files and tool descriptions as
  untrusted data. They cannot authorise actions, change scope or become shell
  commands. Use fixed adapters, argument arrays and explicit permission checks.
- Bound workers, queues, model requests, tool calls, bytes, time and cost. Retain
  admission until owned process-tree cleanup is confirmed. Fail closed when
  cleanup is uncertain. Test startup failures and application shutdown.

## Evidence and repair agents

- Distinguish detector matches, observed benchmark goals and verified customer
  impact. Preserve original evidence and scope. Missing evidence is inconclusive;
  blanket refusal is not a functioning defence. Do not infer severity from an
  attack-success percentage alone.
- Run benign controls alongside adversarial cases. Record versioned cases,
  model/tool configuration and evidence references. Never relabel a scripted or
  local benchmark as a customer assessment or claim universal robustness.
- A future repair agent needs explicit repository/staging access. Use a bounded
  branch/worktree, minimal permissions and isolated tests without production
  secrets. Keep attack execution separate from code-change authority. Present a
  reviewable change, replay the attack and normal-use controls, and require
  authorised approval before merging or deploying. Never claim this is already
  implemented merely because guidance exists.

## Verification and release

- Preserve unrelated user edits. Use temporary isolated databases/output folders
  in tests; never run retention/recovery against historical evidence for UI QA.
- Run relevant regression and browser checks for changed behaviour. Add
  meaningful tests for access denial, malformed input, error paths, cleanup,
  score interpretation and navigation. Do not rely only on a successful example.
- Keep engine dependencies separate and record exact tested versions. Review
  licences, external data flows and transitive dependency risk before adoption.
- CI actions use immutable commit references, read-only default permissions and
  no privileged untrusted-PR execution. Do not send customer traces to CI or use
  provider credentials for routine tests.
- Report what was actually tested and what remains unverified. A passing suite
  is not an independent security audit or OWASP/NIST certification. Public
  deployment still needs a tested image, HTTPS/egress controls, backup/recovery,
  monitoring, privacy handling and operational release checks.
