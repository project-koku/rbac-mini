# Operator swap: insights-rbac → rbac-mini (on-prem)

How `koku-service-operator` runs this binary. The **canonical operator-side
docs** live in the operator repo:
[docs/development/rbac-backend-go.md](https://github.com/project-koku/koku-service-operator/blob/main/docs/development/rbac-backend-go.md)
(COST-8610 / COST-8598).

## 0. Current model (COST-8610 embed)

`spec.rbac.backend: go` uses the **`rbac-mini` binary built into the operator
image** at `/usr/local/bin/rbac-mini`. The operator Dockerfile pins a Mini
git SHA (`RBAC_MINI_REF`). **`spec.rbac.image` is ignored** for the go
backend.

| Item | Value |
|---|---|
| Binary in operator image | `/usr/local/bin/rbac-mini` |
| Workload image | Always `OperatorImage` (`--operator-image` / OLM CSV) |
| Commands | `rbac-mini serve`, `migrate`, `seed`, `bootstrap`, `sync` |
| Bump Mini | Merge Mini → bump `RBAC_MINI_REF` in the operator `Dockerfile` → ship a new operator image |

Earlier drafts used a separately published Quay image
(`quay.io/martin_povolny/rbac-go`). That path is **superseded** by the embed;
keep [LIVE-CLUSTER-TEST.md](LIVE-CLUSTER-TEST.md) only as historical CRC
evidence from that era.

## 1. Open decisions (still relevant)

1. **Multi-org Keycloak sync**: RESOLVED — `sync` without `--org` discovers
   orgs from Keycloak groups (`--org-group-prefix`, default `org-`, env
   `SYNC_ORG_GROUP_PREFIX`), reads per-group `org_id`/`account_number`
   attributes, and syncs members per org. `SYNC_GROUP` is optional and empty
   by default; the org-admin source is the realm role named by
   `SYNC_ORG_ADMIN_SUBGROUP` (default `org-admin`). Single-org `--org` mode
   is kept for tests/ops.
   **Resolution (2026-11-19):** Closed for tracking; no Jira.
2. **Seed parity**: rbac-mini seeds `Cost Administrator` + `Sources
   administrator` (both `admin_default`), the public `Default admin access`
   group, the granular cost-management/sources permission catalog the role
   wizard lists, and the packaged system roles below (operator-parity
   grants, not `admin_default`, not on Default admin access)
   ([rbac_seed/data/](https://github.com/project-koku/koku-service-operator/tree/main/internal/resources/rbac_seed/data)).

   **Expected Mini roles (after COST-8184):**

   | Role | Flags | Notes |
   |------|-------|-------|
   | Cost Administrator | `admin_default` | already seeded |
   | Sources administrator | `admin_default` | already seeded |
   | Cost Price List Administrator | packaged | [COST-8619](https://redhat.atlassian.net/browse/COST-8619) |
   | Cost Price List Viewer | packaged | [COST-8619](https://redhat.atlassian.net/browse/COST-8619) |
   | Cost OpenShift Viewer | packaged | `cost-management:openshift.cluster:*` — [COST-8184](https://redhat.atlassian.net/browse/COST-8184) |
   | Default admin access (group) | `admin_default` | links the two admin_default roles only |

   **Intentionally omitted:** Cost Cloud Viewer (cloud ingest is largely
   irrelevant on-prem). **Must not appear from Mini seed:** Django platform
   junk (Notifications \*, Approval \*, Inventory \*, OCM \*, User Access \*,
   `* Local Test`). Mini replaces Django; junk goes away by not seeding it.
   **Resolution (2026-11-19 / 2026-11-24):** Price List roles —
   [COST-8619](https://redhat.atlassian.net/browse/COST-8619); OpenShift
   Viewer — [COST-8184](https://redhat.atlassian.net/browse/COST-8184).

## 2. API Deployment ([rbac.go: RBACAPIDeployment](https://github.com/project-koku/koku-service-operator/blob/main/internal/resources/rbac.go))

| Current (Django) | rbac-mini (`backend: go`) |
|---|---|
| Image from `spec.rbac.image` | Operator image (`OperatorImage`) |
| `Command: gunicorn`, `Args: rbac.wsgi --bind=0.0.0.0:8080 ...` | `Command: ["/usr/local/bin/rbac-mini", "serve"]`, `Args: ["--addr", ":8080"]` |
| `WorkingDir: /opt/rbac/rbac` | remove (static binary) |
| `rbacEnv()`: `DATABASE_*`, `PGSSLMODE`, `REDIS_*`, … | keep: `DATABASE_*` + `PGSSLMODE` assemble the DSN ([SPEC.md §5](SPEC.md#5-operator-integration)); Redis/Django vars are accepted no-ops |
| Liveness/readiness `GET /api/rbac/v1/status/` | unchanged |
| Port `8080/http`, Service, Envoy `/api/rbac/` route | unchanged |

## 3. Deletions (go backend)

* `RBACWorkerDeployment` (celery) and the beat scheduler: no async work left.
* `KeycloakSyncConfigMap` (embedded Python sync script): replaced by
  `rbac-mini sync`.
* Seed ConfigMap mounts: permission catalog is compiled into Mini.
* `WaitForValkeyInitContainer` on rbac pods: Mini never dials Valkey.
  (Valkey itself stays — koku core still uses it.)

## 4. Migration/seed Job

```
/usr/local/bin/rbac-mini migrate && /usr/local/bin/rbac-mini seed
```

Same Job + revision bump mechanism as Django. Both commands are idempotent.

## 5. Keycloak sync CronJob

```
/usr/local/bin/rbac-mini sync --keycloak-url $KEYCLOAK_URL --realm $KEYCLOAK_REALM \
  --client-id $KEYCLOAK_CLIENT_ID --client-secret $KEYCLOAK_CLIENT_SECRET \
  --org $ORG_ID [--group $SYNC_GROUP] \
  [--org-admin-role $SYNC_ORG_ADMIN_SUBGROUP] [--prune-orphans=$SYNC_PRUNE_ORPHANS]
```

Env names map 1:1 except org/group resolution (see §1.1).

## 6. Database

Same `costonprem_rbac` database, Mini tables
([SPEC.md §3](SPEC.md#3-data-model-11-tables--sqlite--postgres-portable)).
They coexist with Django tables; drop the old ones in a later release.
`waitForRBACDB` initContainer unchanged. When the operator sets
`PGSSLMODE` from `spec.database.sslMode`, Mini honors it on the assembled
Postgres URL (user/password are URL-encoded).
**Resolution (2026-11-19):** Keep Django tables until after next-year GA so
rollback to insights-rbac stays possible; no Jira for now.

Mini and Django table sets are **disjoint** (Mini: `tenants`, `principals`,
`groups`, `roles`, …; Django: `api_*` / `management_*`), so a backend flip in
either direction never deletes or rewrites the other side's data (see
[§7 "Data on rollback"](#data-on-rollback-backend-flip), COST-8621).

## 7. Upgrade / rollback note

Tracked in [COST-8620](https://redhat.atlassian.net/browse/COST-8620).

**Findings**

* With `backend: go`, the Mini binary is embedded in the operator image
  (`/usr/local/bin/rbac-mini`, pinned by `RBAC_MINI_REF` in the operator
  Dockerfile); `spec.rbac.image` is ignored.
* A CMSC `status.upgrade` / CR rollback restores the CR **spec** only. It
  does **not** bring back the previous Mini binary. Getting the previous
  Mini requires rolling the operator Deployment back to the previous operator
  image (image pin / Deployment rollback).
* The database never rolls back with either. Before schema versioning,
  `store.Migrate` was idempotent but unversioned, so an older binary could
  open a newer schema and "work" until it silently misbehaved.

**Recommendation: forward-only.** The DB schema only moves forward; there are
no down-migrations and no expand/contract framework. An older binary that
includes the guard refuses to run against a newer schema instead of guessing;
images released before schema versioning have no such check (see Findings),
so do not roll back to one and expect protection.

**Guard behavior**

* `store.Migrate` stamps a single-row `schema_version` table with the
  binary's `store.SchemaVersion` (currently `1`; bumped with every schema
  change). Stamping is idempotent.
* Before applying any DDL, `Migrate` reads the stamp. If it is **newer** than
  the binary's `SchemaVersion`, it returns an error and changes nothing (the
  stamp is never rewritten by a refused run). The stamp itself is monotonic:
  it never lowers a version, and a run that finds a newer stamp after
  migrating fails rather than reporting success.
* Every entry point (`serve`, `migrate`, `seed`, `bootstrap`, `sync`) goes
  through `prepareDB` → `Migrate`, so after an operator image rollback to an
  image that includes this guard, the migrate Job fails and `serve`
  crash-loops with `database schema version N is newer than this binary (M):
  the operator image was rolled back — …`. That is intended: loud, not
  silent. The refusal applies only when the rollback target contains this
  check; images released before schema versioning run an unversioned
  `Migrate()` and do not refuse.
* A database created before versioning has no stamp row (version 0): it
  migrates forward and is stamped.
* There is deliberately **no bypass flag or env var**.

**Recovery paths** (pick one)

1. **Roll the operator image forward** to a release whose Mini
   `SchemaVersion` is at least the database's. This is the normal fix.
2. **Restore the database** from a backup taken before the upgrade, then run
   the older operator image. Data written since the upgrade is lost.

### Data on rollback (backend flip)

Tracked in [COST-8621](https://redhat.atlassian.net/browse/COST-8621).
Decision (2026-11-27): no coexistence mechanism; rollback is non-destructive
by construction.

* Mini and insights-rbac use separate table sets in the same
  `costonprem_rbac` database ([§6](#6-database)). Neither backend's
  migrate/seed/sync can address the other's tables, so Django's
  `manage.py seeds` cannot prune Mini rows. Mini code has no
  `DROP TABLE` / `TRUNCATE`; its seeds are idempotent upserts.
* Rolling back to `backend: django` makes Django serve **its own** tables,
  frozen at their pre-flip state. Mini-era groups/policies are invisible
  there (not deleted), and `/access/` reflects Django-era defaults.
* Changes made while on Mini stay in Mini's tables and reappear on the next
  flip to `backend: go`. Re-running bootstrap is not needed after a
  rollback; it only matters when Mini tables are fresh (new cluster/DB).
* **Beta limitation:** Django-era custom RBAC config (custom groups, roles,
  assignments) does not carry into Mini. Mini starts from seeded defaults +
  Keycloak-synced principals. Org admins are unaffected (admin defaults are
  seeded on both sides); non-admin users whose access came from custom Django
  groups need that config re-created while on Mini.

## 8. Verification

1. `make test-postgres` green against a scratch Postgres.
2. Operator e2e personas when a `backend: go` job exists (beta today: unit
   tests + manual CRC smoke — see operator
   [rbac-backend-go.md](https://github.com/project-koku/koku-service-operator/blob/main/docs/development/rbac-backend-go.md)).
3. Gateway/IQE bootstrap uses
   `rbac-mini migrate && rbac-mini seed && rbac-mini bootstrap --org … --users …`.
   Bootstrap ensures **Sources administrator**, strips leftover **Cost
   Administrator**, and creates `type=service-account` principals so Keycloak
   sync prune cannot remove gateway usernames such as `cost-mgmt-operator`
   ([COST-8231](https://redhat.atlassian.net/browse/COST-8231)).
