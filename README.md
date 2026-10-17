# Hacker — authorized web application security testing platform

Phase 1 MVP. See [`docs/architecture.md`](docs/architecture.md) for the full
design and [`docs/roadmap.md`](docs/roadmap.md) for what's deliberately not
built yet.

## What's here

```
packages/scanner-core/   The scanning engine. Framework-agnostic, fully
                          unit-tested, no DB/HTTP-server dependency.
apps/api/                Fastify + Prisma + Postgres API. Auth, projects,
                          scope/authorization, scan orchestration, SSE
                          live progress, findings, reports, audit trail.
apps/web/                Next.js dashboard.
infra/                   docker-compose for local Postgres (+ Redis, not
                          yet wired — see apps/api/src/services/queue.redis.md)
```

## Run it locally

Requires Node 20+ and Docker.

```bash
# 1. install everything
npm install

# 2. start Postgres (+ Redis, unused for now)
docker compose -f infra/docker-compose.yml up -d

# 3. configure the API
cp apps/api/.env.example apps/api/.env
# edit apps/api/.env: set JWT_SECRET and MASTER_ENCRYPTION_KEY
#   openssl rand -base64 48   -> JWT_SECRET
#   openssl rand -base64 32   -> MASTER_ENCRYPTION_KEY

# 4. generate the Prisma client and apply the schema
cd apps/api
npm run prisma:generate
npm run prisma:migrate -- --name init
cd ../..

# 5. run everything
npm run build --workspace packages/scanner-core
npm run dev --workspace apps/api     # http://localhost:4000
npm run dev --workspace apps/web     # http://localhost:3000
```

Register an account at `localhost:3000/register`, create a project, define
scope (this is required — a scan cannot start without it), add a target,
and start a Quick scan.

## Current scan coverage and limits

The scanner crawls in-scope pages, fingerprints technologies, checks common
security headers and cookies, looks for exposed files and client-side secrets,
reviews public privacy/terms/security-contact pages, reads published OpenAPI
specifications, and checks documented protected GET routes with an owner-
provided test role and an anonymous request. When active testing is authorized,
it runs bounded GET probes for injection indicators, path traversal, redirects,
privileged paths, and ID-based access-control issues. Results include evidence
and confidence levels; a scanner signal still needs human validation.

Every scan requires a recorded authorization statement. By default, a live DNS
TXT proof is also required for each in-scope host. For temporary local testing,
operators may set `DNS_VERIFICATION_EXEMPT_HOSTS` to a comma-separated list of
exact hostnames; wildcard entries are ignored, and a bypass only applies when
that exact hostname is itself in the project's authorized scope. The scan audit
records when proof was skipped. Remove the setting to require DNS proof again.
Only organization owners/admins can authorize active tests or deep scans. Every
target request also passes through host/path scope, DNS/SSRF, rate, duration,
request-budget, and per-request timeout checks. Cancellation aborts in-flight
HTTP requests. The shared HTTP client allows only GET, HEAD, and OPTIONS. It
never submits credentials, guesses passwords, or sends write methods. When
active testing is disabled, the HTTP client blocks active-testing,
authenticated-comparison, and fixed-path enumeration stages; the engine also
skips OpenAPI route requests and reports that skip in scan events. The crawler
still fetches in-scope target pages and discovered links to perform baseline
discovery and passive checks.

Findings use separate confidence and verification fields. Rule-specific
evidence checks downgrade unsupported claims to suspected or inconclusive;
heuristic probe findings are capped at medium confidence, and a single timing
observation is low confidence. No current check can label a finding
independently verified. Scan events are timestamped and stored by session, and
authorization, verification, blocked scan, and scope changes are recorded in
the audit trail.

This is an automated web/API assessment tool, not a replacement for a skilled
penetration test. It does not test business logic comprehensively, prove legal
or policy compliance, audit source code or cloud configuration, or prevent
ransomware. DNS control proves domain control, not a requester's employment or
authority to test a particular company system. Requester/company authorization
verification is not yet built; the recorded authorization statement remains an
attestation, so use it only for systems you are authorized to assess.

See [`docs/roadmap.md`](docs/roadmap.md) for the next product milestones.
# Scan execution profiles and validation benchmark

Scan jobs are persisted in PostgreSQL and claimed with conditional state
transitions and expiring worker leases. A worker that loses its lease cannot
complete the job; expired read-only scans are restarted from the beginning
after clearing partial findings, with a three-attempt ceiling. The worker
rechecks the project scope version before requests. Process restart recovery
does not provide CPU or memory isolation, and a paused old process can still
consume resources until its lease is noticed.

Quick and CI run bounded discovery and passive checks. Standard adds
authorized read-only active checks and API route comparison. Deep adds more
discovery and matched repeat timing checks. Every profile is capped by the
scope's request and duration limits, and active capabilities remain disabled
when target authorization disallows them. Scan results persist a capability
report; multi-identity object checks, browser JavaScript execution, dependency
advisory analysis, adaptive planning, and independent verification are marked
unavailable.

Run the deterministic synthetic injection-validator benchmark with:

```sh
npm run benchmark --workspace @hacker/scanner-core -- security-benchmark-results.json
```

It records three repetitions of positive and safe in-process fixtures for SQL
error, reflected XSS, path traversal canary, template evaluation, open redirect,
and control comparisons. Command injection is explicitly unavailable because
no command payloads are sent. It performs no network requests and
does not measure real-server detection accuracy or end-to-end scanner runtime.
The JSON labels this limitation and reports fixture counts, precision, recall,
repeatability, request counts, runtime, confidence, and verification state.
