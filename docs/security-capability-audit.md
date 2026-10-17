# Deep Technical Capability Audit

**Repository:** `hacker-platform`
**Audit date:** 2026-10-16
**Method:** Static review of repository implementation, routes, data model, tests, fixtures, deployment configuration, and lockfile. No application target was scanned.

## Executive assessment

This repository contains an early deterministic web-scanner prototype. Its executed path is:

1. `POST /api/projects/:projectId/scans` checks project membership, the active scope version, owner/admin role for active or deep scans, an authorization statement, and DNS TXT control proofs.
2. `InMemoryScanQueue` starts the scan in the API process.
3. `executeScan()` reloads the scan and related project/scope/auth configuration, rechecks the user role and DNS proof, and calls `scanner-core.runScan()`.
4. `runScan()` validates targets, fetches seed targets, crawls pages, probes common paths, fingerprints a small set of technologies, runs passive checks, optionally runs active GET probes, correlates observations, scores findings, and emits events.
5. The API persists endpoints/findings and streams progress over SSE. Per-scan JSONL logs are written to a scan-specific directory. Reports are JSON, CSV, or Markdown; PDF returns HTTP 501.

The application is **not yet an expert red-team platform**. It has useful baseline checks, but no AI agent, no adaptive investigation, no source/dependency analysis, no durable isolated workers, no benchmark demonstrating precision/recall, and no strong evidence that its active findings are reproducible. The `DEEP` profile increases crawl limits to 400 pages and depth 6; it does not select a richer set of checks.

### P0 trust blockers

- `checks/cookies.ts` stores raw `Set-Cookie` values in finding evidence. Findings are persisted and streamed; the JSONL redactor does not remove secrets embedded in arbitrary text values. Session cookies can therefore enter the database, SSE payload, logs, and exports.
- `routes/audit.ts` exposes audit-event deletion to every role except `VIEWER`, despite documentation describing the audit trail as append-only.
- The new DNS TXT proof demonstrates DNS-zone control, not a company’s authority to test a system. There is no independent customer/approver verification, expiry, or revocation check at worker execution.
- The scan route accepts an `authConfigId` without checking that it belongs to the same project as the scan. The worker then loads and decrypts that config’s secret.

## Capability matrix

Statuses describe the executed scan path, not code that merely exists or UI/README claims.

| Capability | Current implementation / status | Repository evidence | Actual technical depth | Important missing functionality | Recommended improvement | Difficulty | Priority |
|---|---|---|---|---|---|---|---|
| Attack-surface discovery | **Partially implemented.** Seeded targets, same-origin links, robots/sitemap, script URLs, 25 fixed paths, JSON OpenAPI/Swagger GET routes. | `packages/scanner-core/src/engine.ts`: `runScan`; `crawler.ts`: `crawl`; `checks/apiSurface.ts`: `discoverApiSpecGetRoutes` | Bounded static HTML crawl. Script files are fetched but not parsed for routes. | No subdomain or asset inventory, passive DNS, ports/services, JavaScript parsing/execution, GraphQL, authenticated route mapping, or completeness tracking. | Build a provenance-tagged asset graph from owner-provided seeds, in-scope JavaScript parsing, API specs, and route normalization. | High | P1 |
| Technology fingerprinting | **Implemented but insufficiently tested.** | `packages/scanner-core/src/techDetection.ts`: `RULES`, `detectTechnologies` | About a dozen simple header/body signatures; often name-only. | No robust version confidence, component inventory, or advisory correlation. | Combine evidence sources, test signatures, report confidence and unknowns explicitly. | Medium | P2 |
| SQL injection | **Implemented but insufficiently tested.** | `packages/scanner-core/src/checks/injection.ts`: `checkSqliGetParams` | Fixed query-string error probes and single MySQL/Postgres timing probes. | No body/form testing, paired baseline/control, context-aware parameter mapping, reproducible proof, or safe validation. A single delay can be noisy and costly. | Use bounded context-aware probes with baseline/control pairs and rule-specific confirmation; label a signal unconfirmed until reproducible. | High | P1 |
| XSS / output handling | **Implemented but insufficiently tested.** | `checks/injection.ts`: `checkReflectedXss` | Three fixed strings sent as GET parameters; checks exact reflection in HTML. | No HTML/JS context parsing, escaped/inert reflection distinction, DOM/stored XSS, or browser proof. | Add context-aware parsing and isolated browser verification; distinguish reflection from executable XSS. | High | P1 |
| SSTI, traversal, redirect, command injection | **Implemented but insufficiently tested.** | `checks/injection.ts`: `checkSsti`, `checkPathTraversal`, `checkOpenRedirect`, `checkCommandInjection` | Small GET-only canaries; SSTI matches `49`; traversal uses a few OS-file indicators; blind command injection uses one 5-second timing observation. | Little context awareness, no reliable baseline, no repeatability. Time-delay probes can be disruptive and produce false positives. | Apply explicit per-check risk and budgets; disable blind delay checks by default until paired timing and staging controls are reliable. | High | P1 |
| Authentication and session | **Partially implemented.** | `checks/authentication.ts`; `engine.ts` imports only `checkSessionTokenEntropy` and `checkPasswordInUrl`; `checks/governance.ts` | Token length/entropy heuristic, URL-secret detection, visible password-form hints, and limited protected-API anonymous comparison. | Brute-force/default-credential POST functions are dormant and blocked by the GET-only client. `LOGIN_FLOW` and `API_KEY` config options are not executed by the worker. No login flow, MFA, expiry, reset, fixation, CSRF, or lifecycle tests. | Support owner-created least-privilege test accounts and explicit session lifecycle checks; never guess credentials. | High | P1 |
| Broken access control / IDOR | **Implemented but insufficiently tested.** | `checks/authorization.ts`: `checkSequentialIdor`, `checkPrivilegedPathAccess`; `checks/apiSurface.ts`: `compareAnonymousAccess` | Guesses up to three nearby numeric IDs and flags a 200 response over 50 bytes; probes 21 fixed admin paths per discovered endpoint. API comparison covers only documented protected GETs. | No second identity or ownership oracle, no role matrix, no object/business context, and no UUID comparison despite comments. A nonempty 200 is not proof of cross-user access. | Compare access for two owner-created test identities and known synthetic objects; deduplicate probes per origin/endpoint. | High | P1 |
| SSRF | **Missing.** | No target-application SSRF check module. `httpClient.ts` only guards the scanner’s own outbound network. | The scanner blocks some private destinations for its own transport; it does not test whether the application makes unsafe server-side requests. | No controlled callback verifier or target-context SSRF evidence. | Add only as a separate opt-in callback-based check, with one-time canaries, strict egress controls, and no access to internal addresses. | High | P2 |
| Path traversal / file handling | **Partially implemented.** | `checks/injection.ts`: `checkPathTraversal`; `crawler.ts` records form fields | GET query parameters with file/path-like names receive a small payload set. | No upload/download, multipart, archive extraction, encoding variants, or authorization-aware file tests; forms are never submitted. | Use safe staging fixtures and canary files; model upload and download schemas; keep writes disabled without a reversible test harness. | High | P2 |
| Security configuration and exposure | **Implemented but insufficiently tested.** | `checks/headers.ts`, `cookies.ts`, `infoDisclosure.ts`, `cachingAndSecrets.ts`; `engine.ts`: `SENSITIVE_PATH_PROBES` | Selected headers/cookies, stack/debug/version patterns, common sensitive paths, client-secret signatures, and cache checks. | Shallow CSP semantics, fixed path list, no TLS/certificate posture, cloud/storage exposure, or broad configuration profile. Fixed-path GET enumeration runs even when active testing is disabled, so scans are not strictly passive-only. | Improve semantic checks and TLS evidence; redact secrets before persistence; label informational results separately from vulnerabilities. | Medium | P1 |
| API discovery / authorization | **Partially implemented.** | `checks/apiSurface.ts`: `discoverApiSpecGetRoutes`, `compareAnonymousAccess`; `engine.ts` | Reads JSON Swagger/OpenAPI `paths`, selects GET, replaces variables with `scan-probe`, and compares protected route responses with an anonymous response. | No YAML, GraphQL, schema fuzzing, BOLA with two identities, property/function authorization, or business-flow checks. | Validate OpenAPI and build bounded schema-driven checks plus identity-paired GET authorization comparisons. | High | P1 |
| Business logic / stateful workflows | **Missing.** | No workflow engine in `packages/scanner-core/src/engine.ts` | Fixed sequential stage list; no adaptive workflow planning. | No state transitions, invariants, transaction replay, race testing, or multi-step role comparisons. | Start with human-authored workflows in disposable staging tenants; later add bounded state-aware planning with teardown. | Very high | P2 |
| Dependencies / exposed services | **Missing.** | No dependency advisory matching or service scanner integration in `apps/` or `packages/`; `package-lock.json` installs this app’s dependencies only. | Banner fingerprints cannot establish a complete customer dependency graph. | No customer SBOM/lockfile intake, CVE matching, container image scan, ports, or services. | Accept customer-provided SBOM/lockfile/artifact and match exact package versions against maintained OSV/NVD data. | Medium | P2 |
| Governance / policy documents | **Implemented but insufficiently tested.** | `checks/governance.ts`: `reviewPublicDocuments` | Checks whether a few reachable pages expose privacy/terms links, security.txt, API docs, and password-form hints. It explicitly avoids legal-compliance conclusions. | Cannot prove a policy is absent, accurate, adequate, or legally compliant. | Keep informational; report pages reviewed and uncertainty; require qualified human review for legal adequacy. | Low | P3 |
| Verification / evidence / correlation / scoring | **Partially implemented.** | `correlation.ts`: `correlateFindings`; `riskScoring.ts`: `riskScore`; `types.ts`: `Finding`, `Evidence` | Groups by rule and host/path, normalizes numeric ID segments, stores up to 10 evidence items, then multiplies hand-set severity/confidence/verification weights. | No rule-specific corroboration, baseline linkage, evidence hashes, stable cross-scan identity, calibrated false-positive model, or impact/context scoring. Some heuristic narratives overstate evidence. | Redact evidence at capture, add check-specific validators, stable finding keys, fixture-calibrated confidence, and precise uncertainty. | High | P0 |
| Reports | **Partially implemented.** | `apps/api/src/routes/reports.ts`: `buildReportJson`, `buildMarkdown`, `buildCsv` | JSON, CSV, and Markdown include scan metadata and findings; PDF intentionally returns 501. | No coverage/limitations statement, full evidence provenance, report audit logging, or generated PDF. | Include scope lease and evidence provenance, coverage gaps, and confidence limits in every report. | Medium | P1 |
| AI agent / orchestration | **Missing.** | No AI SDK, prompts, model config, planner, or agent loop found under `apps/` and `packages/` | Predetermined stages and fixed checks; not autonomous. | No adaptation, memory, uncertainty resolution, or prompt-injection surface today. | If added, let a model propose typed tests only; enforce each action in a separate policy executor and treat target content as untrusted. | Very high | P3 |
| Scope and DNS authorization | **Partially implemented.** | `scope.ts`: `validateScope`; `httpClient.ts`; current uncommitted `apps/api/src/services/targetVerification.ts`, `routes/scans.ts`, `services/scanOrchestrator.ts` | Host/path checks on requests and redirects, private-IP DNS preflight, immutable scope versions, DNS TXT proof at scan creation and worker start, owner/admin requirement for active/deep, free-text authorization statement. | DNS control is not customer authority. No lease expiry/revocation, no worker check that the scope remains active, no independent approval evidence, incomplete IPv6 reserved-address coverage, DNS preflight/fetch TOCTOU. IP-range scope is not fully enforced. | Add signed, expiring, revocable assessment authorization and independent egress enforcement with comprehensive IPv4/IPv6 rules and DNS pinning. | Very high | P0 |
| Worker / timeout / resilience | **Partially implemented.** | `services/scanQueue.ts`: `InMemoryScanQueue`; `scanOrchestrator.ts`; `httpClient.ts`; `queue.redis.md` is documentation | Same-process in-memory queue, concurrency 2, sequential checks, request/rate/duration checks before requests, cooperative cancellation between stages/endpoints. | Jobs disappear on restart; no isolated worker, no fetch abort timeout, no durable queue or bounded distributed events. A stalled request can exceed the scan duration. | Use durable queue and isolated workers with hard wall-clock, memory, request, and network quotas; add idempotent event writes and safe retries. | High | P1 |
| Authentication / tenancy / secret handling | **Partially implemented.** | `routes/auth.ts`, `plugins/authPlugin.ts`, `lib/auth.ts`, `lib/crypto.ts`, Prisma schema | Argon2id, 12-hour JWT cookie, session-version invalidation, organization membership checks, auth endpoint rate limit, AES-256-GCM auth-secret storage, hashed password-reset token. | Master key is a single env secret; no MFA/email verification; reset depends on email setup. Scan `authConfigId` is not checked against scan project. Audit deletion is permitted to non-viewers; target creation permits viewers. | Enforce tenant/project ownership for every foreign ID, use KMS, add identity controls, and restrict destructive actions. | High | P0 |
| Audit trail / scan logs | **Partially implemented.** | `services/auditLog.ts`, `routes/audit.ts`, `services/scanSessionLog.ts`, `routes/scans.ts` | Timestamped per-scan JSONL plus database audit events; URL query secrets and secret-like field names receive basic redaction. | Audit events can be bulk-deleted through API; database administrators can alter records. Raw Set-Cookie evidence is not removed by current string redaction. No retention/size limit or external immutable sink. | Redact before DB/SSE/logging, remove routine audit deletion, add retention and a tamper-evident external sink. | High | P0 |
| Tests / benchmark | **Implemented but insufficiently tested.** | `packages/scanner-core/src/__tests__/` (9 test/fixture files); `apps/api/src/__tests__/` | Unit tests cover pure checks, scope, HTTP behavior, scoring and small fixtures. | No end-to-end scan harness, labeled benchmark, per-rule precision/recall, WSTG/ASVS coverage, or authorization/tenant abuse suite. | Add local vulnerable and safe fixture apps, versioned expected evidence, and CI metrics for precision, recall, repeatability, request/time cost, and crash rate. | High | P1 |
| Dependencies / deployment | **Partially implemented.** | Workspace manifests, lockfile, Dockerfiles, `infra/docker-compose.yml`, `render.yaml`, `DOCKER_NGROK.md` | Docker/local-tunnel and Render configurations exist. Locked versions observed: Fastify 5.12.5; Next.js 16.4.1; Prisma 5.22.0; Cheerio 1.2.0; argon2 0.41.1; Vitest 4.1.11; TypeScript 5.9.3. | No CI evidence, dependency scan artifact, KMS, durable isolated workers, or external log sink. `npm audit` at audit time reported zero known advisories; this does not establish application security. | Add CI security/quality gates, deployment smoke checks, pinned worker images, durable queue/DB/KMS and network egress policy. | High | P1 |

## Ten highest-value improvements

### 1. P0 — Prevent sensitive evidence and audit leakage

- **Today:** Cookie evidence includes raw `Set-Cookie`; finding events are persisted and written to JSONL. Audit events can be deleted by non-viewers.
- **Change:** Redact at capture and again before database, SSE, logs, and exports. Store only attributes or a non-reversible fingerprint, never the cookie value. Remove routine audit deletion or require a break-glass owner action sent to an external immutable store. Add retention and log-size limits.
- **Affected modules:** `checks/cookies.ts`, `httpClient.ts`, `scanOrchestrator.ts`, `scanSessionLog.ts`, `routes/audit.ts`, report serializers.
- **Validation:** Use synthetic secret canaries and prove they never appear in DB evidence, event streams, JSONL, CSV/Markdown/JSON exports, or error logs. Test audit deletion authorization per role.
- **Success:** Zero canary secrets in persisted/exported artifacts; tamper-evident audit events; complete negative role tests.
- **Safety impact:** Blocker before customer data is assessed.

### 2. P0 — Replace self-attestation with revocable assessment authorization

- **Today:** DNS TXT proves control over a zone; a free-text statement self-attests authority. Worker rechecks role and DNS but not expiry, revocation, or active scope status.
- **Change:** Create a signed assessment lease with verified customer/legal entity, approver and evidence reference, precise hosts/paths/IPs, permitted test classes, environment, request/rate/time limits, start/expiry, revocation, and emergency stop. Enforce it at enqueue, worker start, and every outbound request.
- **Affected modules:** Scope/authorization schema, `routes/scope.ts`, `routes/scans.ts`, `scanOrchestrator.ts`, `scope.ts`, `httpClient.ts`, scope UI.
- **Validation:** Mock time and DNS; test expired, revoked, replaced, wildcard, cross-tenant, and queued-before-revocation cases. No network request may follow revocation.
- **Success:** Every outbound request maps to a valid signed lease; zero stale-scope jobs; audit records actor, approver, scope digest, and expiry.
- **Safety impact:** Describe DNS proof as control proof only. Keep unsupported IP-range scans blocked.

### 3. P1 — Harden outbound network enforcement

- **Today:** Host/path and DNS private-address checks run before fetch and redirects are rechecked. DNS resolution and actual socket resolution are separate; IPv6 coverage is incomplete; fetch has no abort timeout.
- **Change:** Route all worker traffic through an isolated egress proxy that validates and pins socket destinations, blocks private/reserved IPv4 and IPv6, and enforces per-host allowlists. Add hard request timeout, body cap, and worker quotas.
- **Affected modules:** `scope.ts`, `httpClient.ts`, worker/deployment networking.
- **Validation:** Local integration fixtures for mixed DNS answers, redirects, DNS rebinding, slow/oversized responses, cancellation, URL parsing edge cases, and each blocked address range.
- **Success:** Zero out-of-scope egress; all requests terminate within the configured deadline.
- **Safety impact:** Network policy must remain an independent control from scanner code.

### 4. P1 — Make injection checks evidence-first and context-aware

- **Today:** Fixed GET payloads and simple substring or single-delay rules can yield high-impact narratives without strong proof.
- **Change:** Model each check as a bounded plan with baseline/control requests, input context, normalization, stop criteria, and check-specific confirmation. Separate candidate signal from confirmed vulnerability. Disable blind delays by default until paired controls are reliable.
- **Affected modules:** `checks/injection.ts`, endpoint/input types, `httpClient.ts`, correlation and report schemas.
- **Validation:** Versioned local vulnerable and safe fixtures, including encoded/escaped cases, noisy responses, and false-positive controls.
- **Success:** Per-rule precision, recall, repeatability, requests per confirmed finding; all claims trace to paired evidence.
- **Safety impact:** Keep default requests read-only and tightly budgeted; state-changing checks need disposable staging and a reversible harness.

### 5. P1 — Add real authenticated role and object-authorization testing

- **Today:** A configured cookie or bearer token is attached to requests. Only OpenAPI-declared protected GET routes receive a simple anonymous comparison. Sequential IDs are not compared across separate identities.
- **Change:** Support owner-created test identities, explicit roles and credential expiry. Compare anonymous, low-privilege, and owner access to known synthetic reference objects; preserve redacted object-identity evidence. Add session lifecycle and CSRF checks.
- **Affected modules:** `AuthenticationConfig`, `AuthContext`, `apiSurface.ts`, `authorization.ts`, orchestrator, UI.
- **Validation:** Local multi-tenant lab with known role/object access matrix, stale credentials, session expiry, and secret-redaction checks.
- **Success:** Route/role coverage, seeded authorization defect detection, no cross-account secrets in evidence, reproducible results.
- **Safety impact:** Synthetic test accounts only; no employee credential guessing.

### 6. P1 — Make profiles and check permissions explicit

- **Today:** Profiles mostly change crawl limits. `enabledModules` exists in a type but the engine does not use it to select modules.
- **Change:** Create a check registry with required inputs, traffic class, risk, permission, request/time budget, evidence schema and version. Show requested, executed, skipped and unavailable checks in every report.
- **Affected modules:** `engine.ts`, `types.ts`, API scan schema/config, Prisma `ScanConfig`, UI, reports.
- **Validation:** Assert per-profile manifests and ensure disabled/high-impact modules never run; enforce per-module budgets.
- **Success:** Complete module traceability; no advertised scan check without execution evidence.
- **Safety impact:** Default to low-impact checks; higher-risk classes need separate scope approval.

### 7. P1 — Build a reproducible benchmark and coverage map

- **Today:** Unit tests and fixtures exist; there is no labeled scan benchmark, precision/recall report, or complete standards mapping.
- **Change:** Map rules to versioned OWASP WSTG v4.2, ASVS 5.0.0, Top 10 2025, and API Top 10 2023 requirements. Add safe/vulnerable fixtures, exact evidence expectations, regression corpus, and explicit unsupported cases.
- **Affected modules:** Scanner tests, fixture server, CI, rule registry, docs.
- **Validation:** Local-only vulnerable apps, seeded defects and safe analogues, deterministic replay and report snapshots.
- **Success:** Per-rule precision, recall, repeatability, coverage, cost and crash rate, versioned by engine/rule set.
- **Safety impact:** Never use customer sites as a benchmark; isolate fixtures from production secrets.

### 8. P1 — Improve modern SPA/API discovery

- **Today:** Static HTML crawl, links/forms/script URLs, common paths, JSON OpenAPI GET routes. JavaScript is not parsed; no GraphQL or YAML spec support.
- **Change:** Add an isolated browser crawler with request interception; parse in-scope JS/source maps; validate and normalize OpenAPI/GraphQL routes, parameters, auth schemes and provenance.
- **Affected modules:** `crawler.ts`, `apiSurface.ts`, types, worker runtime, endpoint UI.
- **Validation:** Local SPA-only routes, dynamic navigation, source maps, external API references, redirects and hostile out-of-scope requests.
- **Success:** Seeded route recall, reduced duplicates, source provenance, zero out-of-scope browser requests.
- **Safety impact:** Browser workers need isolated storage, disabled downloads/file access, quotas, and the same egress policy.

### 9. P2 — Add defensible dependency/artifact risk assessment

- **Today:** No customer dependency inventory or advisory matcher; server banners cannot reveal full package graphs.
- **Change:** Accept consented lockfiles, SBOMs, or container artifacts; match exact ecosystem/version ranges to maintained OSV/NVD advisories and separate known-vulnerable from reachable/exploitable.
- **Affected modules:** New ingestion and advisory adapter, findings, project upload/API, reports and queue.
- **Validation:** Fixtures for vulnerable/fixed/transitive dependencies, aliases, withdrawn advisories, and unreachable code.
- **Success:** Package/version match precision, feed freshness, provenance and false-positive rate.
- **Safety impact:** Do not run package lifecycle scripts; treat uploaded manifests as sensitive.

### 10. P2 — Make jobs durable, cancellable and isolated

- **Today:** In-memory queue, same API process, no fetch abort timeout, in-memory event history and local-volume logs. Redis adapter is documentation only.
- **Change:** Use a durable queue and isolated worker per assessment; enforce CPU/memory/network/wall-clock quotas, graceful cancellation, idempotent events, safe retries, and durable streaming.
- **Affected modules:** `scanQueue.ts`, `scanOrchestrator.ts`, `eventBus.ts`, Docker/Render config, database and session logger.
- **Validation:** Worker restart at each stage, DB/queue outages, hung requests and cancellation; verify no duplicate findings or stuck jobs.
- **Success:** Jobs survive restart, resource use remains bounded, result persistence is idempotent, cancel latency is measured.
- **Safety impact:** Isolate customer jobs so one hostile target cannot exhaust shared resources.

## Authorization architecture review

| Question | Finding | Evidence / required control |
|---|---|---|
| Is every outbound request host/path checked? | Current scanner requests go through `ScannerHttpClient`; the active-testing permission itself is only enforced by engine control flow, not by the HTTP client policy. | `httpClient.ts` checks host/path and redirects. `engine.ts` still performs fixed sensitive-path GET probes with active testing disabled. Enforce permission class and a current lease at the independent egress boundary. |
| Does domain proof prove company authorization? | No. | TXT proves zone control; `authorizationStatement` is free text. Require verified company, approver, and authorization evidence. |
| Does authorization expire/revoke? | No. | Scope versions are immutable but have no expiry/revocation. Worker does not check `isActive`; queued/running jobs need immediate stop semantics. |
| Can an AI model evade policy? | No model is present in this repository. | No prompts, LLM SDK, or agent loop found. Keep future model actions behind a separate typed policy executor. |
| Are destructive tests prevented? | Write methods are blocked; GET is not inherently harmless. | `httpClient.ts` allows GET/HEAD/OPTIONS; active GET includes delay probes and discovery enumerates sensitive paths. Classify checks by impact and enforce outside the engine. |
| Are credentials protected? | Mixed. Auth secrets are encrypted at rest; cookie evidence has a leakage path. | `lib/crypto.ts`, `checks/cookies.ts`, `scanSessionLog.ts`. Redact before storage and export; add KMS/retention controls. |
| Can findings trigger actions beyond scope? | No automatic exploitation/remediation path was found. | Findings are persisted/reported; remediation state is manual. Preserve this boundary. |
| Are tenant/object references isolated? | Project-access checks exist; foreign-ID binding needs work. | Validate `authConfigId` belongs to the same project before scan creation. Restrict audit deletion; target creation currently permits viewers. |

## Test and operational readiness

Existing tests are primarily unit tests over mocked exchanges and pure functions, plus API auth/crypto and DNS verification tests. The repository has no end-to-end scan harness, labeled vulnerable/safe benchmark, precision/recall results, standards coverage map, or resource-limit/load evidence. This audit did not run application tests. `npm audit` and `npm audit --omit=dev` returned zero known lockfile advisories on the audit date; this is not a security certification.

Before a customer pilot:

1. Eliminate credential leakage from evidence, streams, logs and exports.
2. Add independently verifiable, expiring, revocable customer authorization.
3. Put workers behind enforced egress policy with hard timeouts and resource isolation.
4. Bind every credential/config foreign key to the same project and tenant.
5. Add durable jobs, retention, tamper-evident audit, and a versioned benchmark.

Testing should use local safe/vulnerable fixtures. Track per-rule precision, recall, repeatability, request count, elapsed time, crash rate, scope escapes (target: zero), and secret canaries in stored evidence (target: zero).

## Objective benchmark suite

No benchmark results or ground-truth measurements were found in the repository. The following is a proposed test program; its metrics must be collected before making coverage or accuracy claims.

### Environments and ground truth

- **OWASP Juice Shop:** pin a specific release/container digest and record the included challenges. Use it for representative web/API flaws and browser-facing behavior.
- **OWASP WebGoat:** pin a release and use its lessons as controlled cases for common web vulnerability families and validation logic.
- **DVWA:** pin a release and use only in an isolated local network for classic web vulnerability cases and controlled security-level comparisons.
- **Custom safe/vulnerable fixtures:** add minimal deterministic endpoints for checks those apps do not represent well, including false-positive lookalikes, encoded/escaped output, malformed or incomplete API specs, redirect chains, slow responses, fake sensitive files/soft-404s, cache/header edge cases, and role/object access matrices.

Run these targets only as local test containers on a private test network. Pin images and seed state; do not point benchmark jobs at public deployments. Each case should have a written ground-truth label, the exact rule expected to fire or remain quiet, expected evidence, allowed request count, and teardown/reset steps.

### Separate benchmark tracks

1. **Passive track:** scan fixed fixture snapshots without active probes. Measure discovery and passive rule detection, and confirm the report calls out coverage limits.
2. **Active read-only track:** enable only approved GET/HEAD/OPTIONS tests against fixtures designed for those checks. Record all requests and assert no requests escape the fixture host/path scope.
3. **Authenticated track:** use synthetic accounts and objects in a resettable lab. Measure anonymous, low-privilege, and owner role comparisons without real credentials or customer data.
4. **Isolated-lab verification track:** run checks that need special callbacks or state only in disposable containers with explicit egress denial to the public internet and internal host networks. Keep any state-changing check out of the normal scan path until reversibility and teardown are proven.
5. **Operational track:** restart workers/API at each stage, simulate slow or oversized responses, DB/queue failures, scan cancellation, budget exhaustion, and concurrent tenants.

### Metrics and acceptance gates

- Detection precision = true positives / all emitted positive findings; recall = true positives / all seeded positive cases; record false negatives by rule and fixture.
- Verification accuracy = findings whose evidence meets the rule’s confirmation criteria / findings labeled confirmed. Keep likely/unverified results separate.
- Duplicate rate = duplicate findings beyond the ground-truth issue identity / all findings.
- Performance = requests, elapsed time, peak memory/CPU, crash rate, and p50/p95 per scan and per rule.
- Authorization = out-of-scope requests, requests after lease expiry/revocation, blocked destructive methods, and tenant-boundary violations; required result is zero.
- Data handling = secret canaries in database rows, SSE events, logs, and exports; required result is zero.
- Regression = compare each release against a versioned prior corpus; show per-rule deltas and require review before changing rules or budgets.

Do not roll these into one accuracy number. Publish each metric by rule, scan mode, and fixture version so missed cases and noisy checks remain visible.

## Proposed implementation sequence

1. **Close P0 trust issues:** redact secrets before evidence persistence/streaming/logging/export; restrict audit deletion; bind `authConfigId` to the same project; add tests for all three.
2. **Make authorization revocable and enforceable:** model signed expiring authorization and revocation, verify approver/entity, reject stale scans in the worker, and enforce the lease outside the scanner engine.
3. **Enforce network/worker boundaries:** add destination pinning/egress policy, full private/reserved IP rejection, request abort timeouts, hard resource limits, and durable isolated jobs.
4. **Establish the benchmark harness:** pin Juice Shop, WebGoat, DVWA and custom fixtures; capture the baseline metrics before broadening checks.
5. **Make checks/profiles explicit:** registry with permission class, risk, inputs, evidence schema, budgets, and actually executed/skipped module manifest.
6. **Improve detection in measured increments:** first injection evidence quality, then authenticated authorization tests, then SPA/API discovery and artifact/dependency assessment; each change must improve labeled coverage without exceeding false-positive or safety budgets.
7. **Improve reporting and operations:** expose coverage, uncertainty, scope lease, rule versions, retest/regression comparisons, retention and audit evidence.

This ordering fixes data/authorization trust first, creates measurable ground truth before expanding detection, then adds capability with regression evidence. It is a recommendation only; no scanner code has been changed as part of this audit.

### Recommended first implementation

The highest-value first code change is **secret-safe evidence handling**: remove raw cookie values at the source in `checks/cookies.ts`, ensure redaction occurs before database/SSE/JSONL/report output, then add canary-based regression tests for each sink. The scanner currently processes customer-controlled authentication sessions and can persist raw `Set-Cookie` values. Until that is fixed, increasing assessment depth increases the volume of sensitive data the product may retain. This is a focused, measurable change that protects customers before deeper scans are introduced. Audit deletion and project-binding checks should follow in the same P0 readiness tranche.

## Reference versions and tools

- OWASP WSTG: latest stable is **v4.2**; v5.0 is under development.
- OWASP ASVS: stable release **5.0.0**.
- OWASP Top 10: current release **2025**.
- OWASP API Security Top 10: **2023** edition.
- ZAP Automation Framework: a possible contribution for policy-configurable crawling, passive rules, and OpenAPI workflows, only behind this app’s scope/egress controls.
- OSV-Scanner v2: source/lockfile and container-image package matching complements dynamic web scanning; it cannot replace it.

References: [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide), [OWASP ASVS](https://owasp.org/projects/asvs), [OWASP Top 10](https://owasp.org/projects/top-ten?lang=en), [OWASP API Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x03-introduction/), [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/), [OSV-Scanner v2](https://google.github.io/osv-scanner/usage/), [NVD API](https://nvd.nist.gov/developers/vulnerabilities).

## Audit limits and repository state

The DNS TXT authorization changes referenced above are present in the workspace but were uncommitted during this review. The audit did not scan `wa.tukonectdigital.co.ke` or any external target. Lockfile versions were inspected on 2026-10-16; advisory feeds and standards may change over time.
