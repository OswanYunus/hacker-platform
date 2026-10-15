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

Every target request passes through the scope, DNS/SSRF, rate, duration, and
request-budget checks. The shared HTTP client allows only GET, HEAD, and OPTIONS.
It never submits credentials, guesses passwords, or sends write methods. Scan
events are timestamped and stored by session, and authorization/scope changes
are recorded in the audit trail.

This is an automated web/API assessment tool, not a replacement for a skilled
penetration test. It does not test business logic comprehensively, prove legal
or policy compliance, audit source code or cloud configuration, or prevent
ransomware. Target ownership and requester employment verification are also
not yet built; use it only for systems you are authorized to assess.

See [`docs/roadmap.md`](docs/roadmap.md) for the next product milestones.
