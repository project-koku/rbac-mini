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
([SPEC.md §3](SPEC.md#3-data-model-10-tables--sqlite--postgres-portable)).
They coexist with Django tables; drop the old ones in a later release.
`waitForRBACDB` initContainer unchanged. When the operator sets
`PGSSLMODE` from `spec.database.sslMode`, Mini honors it on the assembled
Postgres URL (user/password are URL-encoded).
**Resolution (2026-11-19):** Keep Django tables until after next-year GA so
rollback to insights-rbac stays possible; no Jira for now.

## 7. Upgrade / rollback note

With `backend: go`, the Mini binary follows the **running operator image**.
A `status.upgrade` rollback restores the CR spec but cannot bring back a
previous Mini binary — that requires rolling the operator Deployment back
to the previous operator image.
**Resolution (2026-11-19):** Investigate CR rollback vs embedded Mini
binary/schema mismatch and implement the safest approach —
[COST-8620](https://redhat.atlassian.net/browse/COST-8620).

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
