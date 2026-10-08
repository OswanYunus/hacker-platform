# Architecture

```
Browser (Next.js)
   |  HTTPS, cookie session
   v
Web API (Fastify)
   |  enqueue
   v
Job Queue (InMemoryScanQueue now; BullMQ+Redis adapter documented)
   |
   v
Scan Workers (same process today; separate containers in production —
   |          see services/queue.redis.md for the isolation checklist)
   v
Scanner Modules (packages/scanner-core)
   |  HttpExchange records
   v
Evidence / Finding persistence (Postgres via Prisma)
   |
   v
Finding correlation + risk scoring -> Findings table
```

## Why scanner-core is a separate package

It has zero dependency on Fastify, Prisma, or any transport. Every check is
a pure function from `HttpExchange -> RawObservation[]`; the crawler and
HTTP client are the only pieces that touch the network, and both take an
injected `AuthorizationScope` they cannot bypass. This means:

- the whole engine is unit-testable without a database or a live target
  (see its 31 tests — mocked exchanges, no network)
- it's reusable from a CLI or a CI action later without dragging in the
  API server
- the scope/SSRF enforcement lives in one place (`scope.ts` +
  `httpClient.ts`) that every current and future scanner module is forced
  through, rather than each module remembering to check

## The authorization boundary, concretely

Three independent layers, so a bug in one doesn't erase the others:

1. **`validateScope()`** (pure function, no I/O) — host allow/deny list,
   path allow/deny list, protocol check, literal private-IP check.
2. **DNS-resolution check in `ScannerHttpClient`** — resolves the
   hostname and rejects it if any resolved address is private/reserved,
   re-run on **every redirect hop**, so a target can't 302 the scanner
   into `169.254.169.254` or an internal service.
3. **Budgets** — requests/second, total requests, total duration, all
   enforced in the same HTTP client, independent of what any scanner
   module thinks it's doing.

None of this is a UI affordance that a module could forget to check —
every request a scanner module issues goes through `ScannerHttpClient`,
which is the only thing in the codebase allowed to call `fetch()` against
a target.

## Data model

See `apps/api/prisma/schema.prisma`. The one deliberate design choice
worth calling out: **`ScopeVersion` is immutable.** Changing scope creates
a new row and deactivates the old one; a `Scan` points at the specific
`ScopeVersion` it ran under. This means the audit trail and any historical
report can always answer "what was authorized when this scan ran,"
not just "what's authorized now."

## Event streaming

`scanner-core`'s engine emits a `ScanEvent` for every stage transition,
discovered endpoint, detected technology, and raised finding. The API's
`scanOrchestrator` both persists these to Postgres (so scan history
survives a restart) and publishes them to an in-memory `ScanEventBus` that
the `/api/scans/:id/events` SSE route streams to the browser, replaying
buffered history first so a client connecting mid-scan isn't missing
earlier stages. If workers move to separate processes, swap
`ScanEventBus`'s internals for Redis pub/sub — the SSE route doesn't need
to change.
