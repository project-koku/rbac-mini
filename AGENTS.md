# rbac-mini – agent guide

The single always-on instruction file for every coding agent working in this
repository.

`rbac-mini` (module `rbac-go`) is an open-source Go replacement for the v1
subset of insights-rbac that on-prem Cost Management needs. Its primary
consumer is the **Cost Management Service Operator**, which can embed and run
this binary:

- Operator: [project-koku/koku-service-operator](https://github.com/project-koku/koku-service-operator)
- Contract and swap notes: [doc/SPEC.md](doc/SPEC.md), [doc/OPERATOR-SWAP.md](doc/OPERATOR-SWAP.md)

> **Versions:** Check [`go.mod`](go.mod) — do not rely on version numbers in docs.

## Quick reference

**Key commands:**
```
make test-sqlite       # default suite (:memory: SQLite)
make test-postgres     # same suite against scratch Postgres 16
make test-cover        # product coverage; fails below 90%
make lint              # go vet + golangci-lint
make build
```

`make test-postgres` expects scratch Postgres on `127.0.0.1:55432`; see the
comment at the top of the [Makefile](Makefile).

**Project structure:**
```
cmd/rbac-go/           # serve, migrate, seed, bootstrap, sync
internal/access/       # GET /access/ hot path
internal/server/       # HTTP handlers and routes
internal/store/        # portable SQL schema, SQLite + Postgres
internal/keycloak/     # Keycloak → principals sync
internal/seed/         # catalog / bootstrap seed data
internal/contract/     # permission-string normalization (ported from koku)
doc/                   # SPEC, OpenAPI subset, operator swap, load test
scripts/loadtest/      # local stress/latency tooling (not product coverage)
scripts/coverage.sh    # product coverage measurement (CI + make test-cover)
```

**Tests:** Prefer real store/HTTP behavior via [`internal/testdb`](internal/testdb/)
and `httptest` over mocks. Product coverage must stay **≥ 90%** of
`./cmd/...` and `./internal/...` excluding [`internal/testdb`](internal/testdb/).
[`scripts/loadtest/`](scripts/loadtest/) is out of scope for the gate.

```bash
make test-cover
COVERAGE_THRESHOLD=95 make test-cover   # optional tighter local check
```

## Critical constraints

1. **Portable SQL** — `?` placeholders only; the store rebinds for Postgres.
   No `DISTINCT ON`, `RETURNING`, JSON operators, or `ILIKE`.
2. **Tenant isolation** — every query is tenant-scoped. Never return another
   tenant's rows.
3. **Access defaults** — platform-default groups (tenant + public) for everyone;
   admin-default only for org admins. Inactive principals (`is_active=0`) get
   an empty access list.
4. **Operator compatibility** — keep env vars, migrate/seed/sync jobs, probes,
   and image embed aligned with how
   [koku-service-operator](https://github.com/project-koku/koku-service-operator)
   deploys Mini. Do not reintroduce SaaS-only insights-rbac surface (Kessel,
   Celery, Kafka, Valkey as a required cache).
5. **API / docs** — public surface changes must update [doc/SPEC.md](doc/SPEC.md)
   and [doc/openapi.v1-subset.json](doc/openapi.v1-subset.json).
6. **Timestamps** — fixed-width UTC TEXT via `store.Now()`; set `created` /
   `modified` where the v1 shape has them.
7. **List filters** — mirror Django (`name_match=partial|exact`, case-insensitive);
   validate enums and return 400 instead of ignoring them.

## When modifying...

| When you modify... | Also update... |
|---|---|
| HTTP handlers / routes | tests under `internal/server/`; OpenAPI subset + SPEC if the public contract changes |
| `internal/store` schema or dialects | migrate tests; both SQLite and Postgres suites |
| `internal/access` | persona/access tests; remember inactive + tenant defaults |
| Seed catalog / roles | `internal/seed` tests; note operator seed Job impact |
| Keycloak sync | `internal/keycloak` failure-mode tests (no half-prune) |
| Env vars / CLI flags | operator docs in [doc/OPERATOR-SWAP.md](doc/OPERATOR-SWAP.md) |
| Docs under `doc/` | keep real links (CI runs `lychee --offline`); do not invent paths |
| Load-test stages | never rewrite `scripts/loadtest/results/baseline/`; see [doc/LOADTEST.md](doc/LOADTEST.md) |

## Agent behavior

**Suggested practice — TDD:** when asked to implement a feature or bug fix,
prefer writing failing tests first, then production code until the tests pass.
That keeps quality high, protects the 90% coverage gate, and reduces
hallucinated APIs or behavior. It is a strong default for agents in this repo,
not a hard block if a human chooses another workflow.

**Ask first when:** the change spans many packages or unclear product
behavior; a failing test may mean wrong expectations rather than a bug;
operator or API contract impact is ambiguous.

**Proceed when:** the task is scoped; the fix follows an established pattern;
acceptance criteria are clear.

**Never:** weaken tests to match broken code; skip assertions to green CI;
silently ignore tenant scope; commit secrets or personal machine paths.

**Always:** fix root causes; run the relevant `make test-*` / `make test-cover`
checks before claiming done; prefer portable SQL and tenant-safe queries.
