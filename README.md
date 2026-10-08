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

### A note on this build environment

This was built in a sandboxed environment with no general internet access
(only the npm registry and a few package hosts were reachable). Two
concrete consequences:

- **`scanner-core` and `apps/api`'s non-Prisma code, and `apps/web`, were
  fully installed, typechecked, unit-tested, and built here** — the numbers
  in the test output are real. `scanner-core` has 31 passing tests covering
  scope/SSRF validation, every passive check, correlation, and risk
  scoring; `apps/api` has 7 passing tests covering crypto and auth helpers;
  `apps/web` builds cleanly with `next build`.
- **Prisma's `generate`/`migrate` could not run here** (they fetch engine
  binaries from `binaries.prisma.sh`, which wasn't reachable). The schema
  was hand-reviewed against every query in `apps/api/src/routes` and
  `services`, but run `npm run prisma:generate` on your machine and skim
  `tsc --noEmit` once more before trusting it blindly — that's the one
  layer I couldn't close the loop on myself.

## What's real vs. what's a documented interface

Per the engineering brief: no placeholder soup, no fake scan results. A
scan today genuinely crawls the target, fingerprints technology, and runs
real passive checks (security headers, cookie flags, CORS, info
disclosure, exposed sensitive files, unsafe caching, client-side secret
patterns) — nothing in a report is fabricated.

What's **not** implemented yet, and says so explicitly in the UI/API
rather than faking it:

- **Active testing modules** (injection, IDOR, authz probing, business
  logic) — the `active_testing` stage runs and logs that it's a no-op when
  scope permits active testing, rather than returning invented findings.
- **PDF reports** — the report endpoint returns `501` for `format=pdf`
  with a clear message; JSON, Markdown, and CSV are fully implemented.
- **Authenticated role-comparison scanning** (anonymous vs. user vs. admin)
  — auth config/secrets are stored and passed to the engine, but the
  comparison logic itself is a Phase 2 module.
- **The Redis-backed production queue** — documented in
  `apps/api/src/services/queue.redis.md` with the exact BullMQ shape to
  drop in; not wired by default because this environment had no Redis to
  test it against. The default `InMemoryScanQueue` works today for local
  dev and small deployments.

See `docs/roadmap.md` for the full phase breakdown.
