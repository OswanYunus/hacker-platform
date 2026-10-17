# Security product roadmap

## Current foundation

- User accounts, organizations, projects, targets, immutable scope versions,
  encrypted test-role secrets, and an append-only authorization audit trail.
- Scan credentials are checked against the selected project when queued and
  again in the worker. Cookie findings retain cookie names and security
  attributes while replacing credential values with `[REDACTED]`.
- The HTTP client enforces active-testing scope by request stage, applies a
  per-request timeout capped by scan duration, and aborts in-flight requests
  on cancellation. Fixed-path enumeration and OpenAPI route requests are
  skipped when active testing is disabled.
- Correlation applies rule-specific evidence requirements. Unsupported claims
  become suspected or inconclusive; existing single-probe heuristics cannot
  produce independently verified findings.
- DNS TXT control proof by default, checked at scan creation and again by the
  worker. Temporary operator exemptions are exact-host allowlists, limited to
  the explicitly authorized hostname, and recorded in scan audit metadata.
  Active and deep scans still require an owner/admin and explicit scope
  authorization.
- A bounded crawler with rate, duration, request-count, DNS, redirect, and
  host/path scope checks.
- Passive web checks for headers, cookies, exposed files, information
  disclosure, unsafe caching, client-side secrets, and public policy/contact
  documents.
- Read-only active GET probes for common injection indicators, path traversal,
  redirect behavior, privileged paths, and ID-based access-control signals.
- Published OpenAPI route discovery and authenticated-versus-anonymous checks
  for documented protected GET routes.
- Timestamped per-scan event logs, live progress, findings, remediation
  tracking, and JSON/Markdown/CSV reports.

Audit events cannot be cleared through the application API. Database operators
can still alter records; an external immutable audit sink and retention controls
remain future work.

The shared HTTP client blocks methods other than GET, HEAD, and OPTIONS. Checks
that require writes, account lockouts, destructive actions, or changes to a
customer's data need an isolated test environment and a separate, explicit
authorization design before implementation.

## Priority 1 — customer trust and scope

- Verify requester identity and company role, and associate the authorized
  person with an organization's verified domain and approval contact.
- Require explicit authorization records, named contacts, start/end times,
  environment selection, excluded paths, request caps, and an emergency stop.
- Make scope decisions visible in the audit trail: actor, verified target,
  scope version, scan profile, modules, request count, and outcome.
- Add a customer-visible test window and rate policy. Stop and alert on scope
  violations, repeated server errors, unexpected latency, or the customer's
  stop request.
- Add retention controls and protect evidence/logs from secrets and personal
  data; make exports access-controlled and auditable.

## Priority 2 — stronger web and API coverage

- Adopt a maintained scanning engine such as OWASP ZAP behind the existing
  scope/rate controls; track its ruleset and scanner version in each report.
- Add JavaScript-rendered crawling for single-page apps and authenticated
  journeys using customer-provided test accounts.
- Add safe API schema checks for OpenAPI and GraphQL, with route-to-role
  coverage and request/response schema validation.
- Improve finding verification with baselines, negative controls, repeated
  evidence, deduplication, and clear confirmed/likely/unverified states.
- Add read-only checks for TLS configuration, cache behavior, CSRF defenses,
  security headers, upload configuration, and common authentication flows.

## Priority 3 — enterprise operations

- Tenant isolation review, SSO/MFA, granular roles, billing/quotas, and
  customer-managed retention.
- Worker isolation, durable queues, per-tenant concurrency, observability,
  failure recovery, and signed audit exports.
- CI integrations, ticketing, evidence-backed reports, and trend tracking.
- A controlled rule update process with version pinning, changelogs, regression
  evaluation, and rollback. Do not silently change what a customer's scan runs.

## Implemented execution and profile foundations (2026-10)

- Scan queue state, lease/heartbeat, cancellation requests, progress, attempts,
  and capability reports are persisted in PostgreSQL. Expired jobs restart from
  the beginning after partial result cleanup, up to three attempts; retries
  still require active scope-version validation.
- Quick, Standard, Deep, and CI have explicit capability and budget definitions.
  Profiles cannot enable active testing when the authorized scope forbids it.
- Deep runs matched repeat timing checks for SQL indicators; input validators
  compare controls and repeat relevant evidence. Command injection remains
  unavailable because the scanner will not execute command payloads. Synthetic
  in-process validator benchmarks are available, but they do not establish
  detection performance on real applications.
- Remaining limits include no OS-level CPU/memory isolation, only one configured
  authenticated identity, no browser runtime, no dependency advisory source,
  deterministic rather than adaptive follow-up, and no independent verifier.

## Work that needs people or a different product

Automated web scanning cannot reliably assess every business-logic flaw,
complex multi-role authorization path, source-code defect, cloud/IAM setup,
mobile client, or ransomware resilience control. Those need source/configuration
access, purpose-built exercises, or expert review. The product should show these
coverage gaps in each report instead of claiming complete protection.
