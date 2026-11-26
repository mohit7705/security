# Implementation ledger

Canonical statuses: `NOT_IMPLEMENTED`, `IMPLEMENTED_NOT_VERIFIED`, `IMPLEMENTED_AND_TESTED`, `NOT_APPLICABLE`. No Step 5 changes in this upload are marked tested because the user explicitly deferred test execution. Code inspection alone is not recorded as tested.

| ID | Requirement | Status | Files / tests | Remaining limit |
|---|---|---|---|---|
| 1.1 | DNS/IP checks on Nuclei, TLS and replay paths | IMPLEMENTED_NOT_VERIFIED | Nuclei runner, TLS posture scanner, PoC replayer | Source paths inspected in this archive call `check_dns=True`; DNS rebinding resistance and proxy-side destination enforcement still need live acceptance |
| 1.7 | Redact personal data in reports | IMPLEMENTED_AND_TESTED | redaction utilities, renderers; Step 1 boundary test | Stored URL values are limited to the configured parameter names |
| 1.10 | Ignore files | IMPLEMENTED_NOT_VERIFIED | `.gitignore`, `.dockerignore`, `.env.example`; Step 5 source update | New ignore patterns in this upload have not been checked against Git/Docker build contexts |
| 1.12 | Retention and cleanup | IMPLEMENTED_AND_TESTED | retention, CLI; Step 1 boundary test | Login-state files are not covered |
| 2.2–2.3 | Provenance and stale-result rejection | IMPLEMENTED_AND_TESTED | orchestrator, stage registry, inventory store; Step 2 regression tests | Existing scan states without recorded artifact hashes or stage contribution snapshots are deliberately rerun rather than reused; full browser/auth acceptance remains environment-dependent |
| 2.5–2.6 | Honest stage status and final report status | IMPLEMENTED_AND_TESTED | discovery stages, orchestrator, report builder; Step 2 pipeline tests | None |
| 2.9 | Cancellation | IMPLEMENTED_AND_TESTED | orchestrator, resource governor, CLI; Step 2 pipeline tests | Not exercised with a real Ctrl+C |
| 3.1–3.3 | Endpoint inventory, templates, JS query routes | IMPLEMENTED_AND_TESTED | endpoint normalizer, API/JS intelligence; Step 3 inventory tests | Remaining Step 3 requirements are open |
| 4.1–4.2 | Browser lab mode and session storage capture | IMPLEMENTED_AND_TESTED | browser manager, crawler; browser lab tests | Chromium launch depends on local browser installation; remaining Step 4 requirements are open |
| 5.6–5.9 | Ownership IDOR, repeat verification, vertical roles | IMPLEMENTED_AND_TESTED | authorization checks; local IDOR integration test | 5.1–5.5 and 5.10 remain open |
| 6.4, 6.6, 6.7, 6.9 | TLS legacy probe, doctor, packaging | IMPLEMENTED_AND_TESTED | TLS scanner, dependency manager, requirements files; Step 5/6 tests | No lockfile; 6.1–6.3, 6.5, 6.10, 6.11 need real tools |
| 7.1–7.4 | Secret verdicts, posture split, host deduplication | IMPLEMENTED_AND_TESTED | PoC replayer, deduplicator, report builder and renderers; Step 7 verdict tests | Secret validity remains a human decision |
| 7.6 | Label internal ranking and avoid implying CVSS | IMPLEMENTED_AND_TESTED | severity assessor; Step 7 verdict tests | CVSS v3.1 Base is calculated only when a complete source vector is available |
| 7.5, 7.7–7.9, 7.12–7.13 | Finding history, AI triage tests, evidence database/manager, CVSS v3.1 Base | IMPLEMENTED_AND_TESTED | `evidence_store.py`, `evidence_verifier.py`, `cvss.py`, `tests/test_06_verification_authorization.py`, `tests/test_07_reporting_evidence.py` | Per-scan SQLite only; CVSS v3.1 Base only and only when a complete vector is supplied; no CVSS v4.0 or Temporal/Environmental scoring |
| 8.1–8.4, 8.9 | CI definition, docs, test folders and ledger | IMPLEMENTED_NOT_VERIFIED | `.github/workflows/ci-and-scan.yml`, `docs/`, `tests/`, Makefile | Workflow was added in Step 5 but has not been run on GitHub |
| 8.5 | Docker and Compose build/run verification | IMPLEMENTED_NOT_VERIFIED | Dockerfile, Compose healthchecks, CI Docker/Compose job | Build and runtime checks are automated in CI but have not been executed |
| 8.7 | Benchmarks against Juice Shop, crAPI, WebGoat and DVWA | NOT_IMPLEMENTED | `tests/benchmarks/` placeholder | Requires Docker and the lab applications |
| 8.8 | Full 15-stage orchestrator run and resume | IMPLEMENTED_AND_TESTED | Pipeline full-run test with local HTTP lab | External scanner tools are not provisioned by the test |
| 8.10–8.16 | Final release acceptance | NOT_IMPLEMENTED | — | Project remains in progress |

Items still open from earlier steps include 6.1–6.3, 6.5, 6.10 and 6.11; 8.5 and 8.7; a dependency lockfile; and the noted Step 1 gaps, including DNS validation in PoC replay. Step 5 repository/CI/benchmark acceptance is tracked separately below.


### Step 2 implementation update (2026-11-26)

- Added stage-owned inventory snapshots under `inventory/contributions/`; the mutable `inventory/unified_endpoints.json` remains a compatibility projection and is no longer declared as a producer-owned stage artifact.
- Declared each discovery producer's own snapshot in the stage registry and stage result. This prevents later discovery stages from replacing an earlier producer's artifact identity.
- Resume now compares every declared artifact's current SHA-256 with the hash recorded at stage completion; schema-valid but modified artifacts are rejected and rerun.
- Canonical upstream fingerprints exclude observation timestamps (`first_observed` and `last_observed`) as well as execution timestamps.
- Added privacy-safe endpoint request metadata (`request_content_type`, allow-listed request headers and value-free JSON/form body schemas); browser network capture records only schema, never raw body values.
- Added regression tests for immutable stage snapshots, modified-artifact rejection and request-metadata redaction.
- Verified: 58 focused orchestration, discovery, authentication, browser-auth, endpoint-contract and full-pipeline tests passed; 1 skipped in the extracted upload.
- Not verified: real Chromium launch, real authenticated target lifecycle, Ctrl+C against a live scanner process, and cross-version migration of existing scan directories. Old scan states without the new contribution artifacts/hash records are not eligible for reuse.


### Step 3 implementation update (2026-11-26)

- OpenAPI/Swagger parsing now resolves bounded local JSON Pointer references for path items, parameters, request bodies and schemas; recursive schema extraction handles nested properties, `allOf`, `oneOf`, `anyOf`, arrays and Swagger 2 body/form-data parameters. External references are not fetched.
- Swagger 2 `host`, `schemes` and `basePath` are now applied only after the declared origin passes scope validation.
- API operation records now preserve request content type and value-free body-field metadata in the canonical endpoint inventory.
- GraphQL introspection now records query/mutation field arguments, required-argument status and return-type metadata. The authorization stage performs bounded, read-only query-root field comparisons across configured identities; it skips mutations, required-argument fields and state-changing-looking field names. Response bodies are fingerprinted, not persisted.
- JavaScript source-map analysis now fetches and parses bounded in-scope source maps. A source map is not called a source-code exposure merely because it returns HTTP 200; the finding requires non-empty embedded `sourcesContent`. Source code contents are never copied into findings.
- Authorization analysis no longer treats `endpoint.authenticated` (the discovery identity) as proof that the endpoint is protected. Anonymous authentication-enforcement findings require an explicit API security declaration.
- Business-logic analysis now builds non-executing workflow hypotheses from catalogued operations, identifies candidate transitions, and records an explicit human-approval gate. No workflow transition or mutation is executed.
- Added regression coverage for Swagger 2 references/base paths, schema composition, GraphQL field metadata and identity comparisons, source-map content exposure, explicit ownership attribution and passive workflow models.
- Verified in the extracted latest upload: 39 focused Step 3 intelligence, inventory, authorization and lab-IDOR tests passed.
- Not verified: real target API/GraphQL behavior, live authenticated sessions, Chromium/browser capture (Playwright remains uninstalled), source-map behavior on a real application, and workflow semantics against application-owned state definitions.
- Existing `tests/unit/test_step3_resources.py::test_process_output_is_bounded` failed in this execution environment because the child Python process did not start before its 5-second timeout (returned 124 with no captured output); this failure is isolated to that resource/process test and was not changed by the Step 3 patch.


### Step 4 implementation update (2026-11-26)

- `ResourceGovernor` now validates finite time budgets, caps combined stdout/stderr output, streams stdout lines to bounded callbacks, distinguishes cancellation and inactivity timeout, and terminates child process groups on budget exhaustion.
- Nuclei now emits periodic process statistics, applies an inactivity watchdog, preserves sanitized scope-validated JSONL events incrementally (including partial runs), records bounded redacted stderr, and treats timeout, cancellation, callback failure, output truncation and non-zero exits as incomplete.
- Nuclei default template exclusions now include intrusive, fuzzing, denial-of-service, brute-force, default-login, token-spray, SQLi and RCE categories.
- `ScopedHttpClient` now enforces response-body byte limits even when constructed without a shared `ResourceGovernor`; requests are streamed and closed on limit violation.
- `testssl.sh` output is accepted only when the process exits successfully and its JSON report is present and parseable. A leftover report file can no longer hide a failed scanner exit.
- Dependency doctor now checks optional testssl binaries and performs a real headless Chromium launch for `browser-enabled` and `full-scanner` profiles instead of treating an installed Playwright module as browser readiness.
- Evidence storage now uses a private verification directory, tightens SQLite file permissions, rejects non-finite numeric evidence, checks evidence-ID ownership collisions and makes integrity/replay audit rows append-only.
- Verification no longer treats a generic HTTP 200 as proof of an unrelated scanner finding. Source-map exposure requires embedded `sourcesContent`; API-spec exposure requires OpenAPI/Swagger markers; Nuclei matches remain human-review candidates pending template-specific matcher reproduction.
- CORS origin reflection is not promoted to a confirmed security issue without browser evidence of credentialed sensitive-response readability. Repeated 5xx responses without causal proof remain human-review items.
- TLS/header posture findings require verified producer-artifact provenance before they can be confirmed as configuration observations.
- Evidence verification now returns `PARTIAL` when a replay crashes, provenance fails, or a finding cannot be completed; target metrics no longer claim every finding was tested.
- Updated the end-to-end CORS reporting assertion to require the human-review queue, and made the GraphQL introspection unit test offline/deterministic rather than relying on external DNS.
- Added Step 4 regression tests for process streaming, inactivity termination, aggregate output limits, response-size limits, evidence-store permissions, non-finite values, CORS review status, HTTP-exposure content contracts, source-map content, posture provenance, failed verification status, testssl return-code handling, Chromium launch checks and incremental Nuclei JSONL persistence.
- Verified in the exact patched extraction: the full test suite passed with 181 passed, 1 skipped and 14 TLS deprecation warnings. The skipped browser-capture test requires the enforced egress proxy; all code-level Step 1–4 selections passed.
- Not verified: real Nuclei/testssl execution against an authorized lab, real browser launch on the user's host, full-scanner doctor on a provisioned machine, OS-enforced CPU/memory/process limits, database migration/backup/retention acceptance, CVSS v4.0 and Temporal/Environmental scoring, and end-to-end category-specific reproduction for all Nuclei templates.


### Step 5 implementation update (2026-11-27)

- 5.1: Restored root repository hygiene files (`.gitignore`, `.dockerignore`,
  `.env.example`) and aligned operator-facing CLI examples with the selected
  executable name `quiver`. The project distribution/import package remains
  `security-analyzer` / `security_analyzer`.
- 5.2: Added `.github/workflows/ci-and-scan.yml`: Python 3.11–3.13 test
  matrix, in-memory syntax compilation, wheel build/install, CLI/stage
  registry smoke checks, Docker/Compose startup checks, non-root assertion,
  proxy health and direct-egress denial assertion. GitHub execution remains
  pending.
- 5.3: Added an opt-in Compose `lab` profile for a pinned OWASP Juice Shop
  container on the analyzer's internal-only network. Added a manual
  `workflow_dispatch` scan job with an explicit single-host/port scope,
  private-IP allowance limited to the isolated Docker lab, conservative
  request/process budgets and no state-changing probes. The lab scan is not
  run by pull requests or normal pushes.
- 5.4: Hardened the offline benchmark scorer: validates report/manifest/state
  contracts and coverage counts, rejects source-file overwrite, writes output
  atomically, ignores non-finite stage durations, and emits JSON `null` for
  precision/recall/coverage when the denominator is zero.
- 5.5: Release acceptance remains open until GitHub Actions, Docker image
  build/Compose smoke, and the explicitly opted-in Juice Shop run complete on
  a clean runner.

Local verification for this Step 5 patch: recorded separately in the
assistant delivery; it does not establish GitHub Actions or Docker runtime
acceptance. No external target was scanned.

### Step 5 remaining acceptance items

- Execute `.github/workflows/ci-and-scan.yml` on GitHub and resolve any
  runner-specific failures.
- Build and start Docker Compose on a clean host; verify non-root UID,
  internal-only analyzer network, proxy health and blocked direct egress.
- Run the opt-in Juice Shop profile and inspect its generated report and
  coverage ledger. The local benchmark scorer is not itself proof of scanner
  detection quality.
- Run controlled ground-truth manifests against the supported lab versions;
  report precision/recall only when the manifest is complete.
- Earlier Step 1–4 carryovers listed above remain release blockers where
  environment-level validation is required.

