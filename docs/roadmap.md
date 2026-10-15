# Security product roadmap

## Current foundation

- User accounts, organizations, projects, targets, immutable scope versions,
  encrypted test-role secrets, and an append-only authorization audit trail.
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

The shared HTTP client blocks methods other than GET, HEAD, and OPTIONS. Checks
that require writes, account lockouts, destructive actions, or changes to a
customer's data need an isolated test environment and a separate, explicit
authorization design before implementation.

## Priority 1 — customer trust and scope

- Verify control of every target domain with DNS or HTTP challenges before
  allowing scans; persist verification evidence and expiry.
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

## Work that needs people or a different product

Automated web scanning cannot reliably assess every business-logic flaw,
complex multi-role authorization path, source-code defect, cloud/IAM setup,
mobile client, or ransomware resilience control. Those need source/configuration
access, purpose-built exercises, or expert review. The product should show these
coverage gaps in each report instead of claiming complete protection.
