# Roadmap

## Phase 1 — shipped in this pass

- Auth (register/login, argon2id, JWT session cookie)
- Projects, targets, versioned+immutable scope, encrypted auth-config secrets
- Crawler (links, forms, JS resource discovery)
- Technology fingerprinting (headers + body signatures)
- Passive scanner: security headers, cookie attributes, CORS misconfig,
  info disclosure/stack traces, exposed sensitive files, unsafe caching of
  authenticated responses, client-side secret patterns
- Finding correlation/deduplication + risk scoring
- Scan history, live SSE progress view, findings dashboard, remediation
  status tracking
- Reports: JSON, Markdown, CSV (PDF returns 501 — not yet built)
- Append-only audit trail wired into every authorization-relevant action
- CI policy evaluation endpoint (`/api/scans/:id/ci-check`)
- Scan comparison endpoint (new/resolved/recurring findings between two scans)

## Phase 2 — next

- Active testing modules: `AuthorizationScanner` (IDOR, horizontal/vertical
  privilege checks via multi-role comparison), `InputValidationScanner`
  (injection indicators with verify-before-claim), `SessionScanner`
  (fixation, rotation-on-privilege-change), unsafe HTTP method probing
- Authenticated/role-comparison scanning using the `AuthenticationConfig`
  data already captured but unused by the engine today
- API-first scanning: OpenAPI spec ingestion -> endpoint inventory;
  GraphQL introspection
- Headless-browser crawling option for SPA-heavy targets (same
  `CrawlResult` interface, so nothing downstream changes)
- PDF report rendering

## Phase 3

- AI analyst layer: operates only on persisted evidence (findings +
  exchanges already in Postgres), for explanation/correlation/prioritization
  — not another thing that talks to the target
- Attack-surface graph visualization
- GitHub Actions / GitLab CI integrations built on the existing
  `ci-check` endpoint and `CiIntegration` table
- Redis-backed `ScanQueue` + separate worker containers (adapter shape
  already documented in `apps/api/src/services/queue.redis.md`)

## Phase 4

- Organization billing/usage limits, team roles beyond the current
  OWNER/ADMIN/MEMBER/VIEWER set, SSO
