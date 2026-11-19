#!/usr/bin/env bash
# Build (if missing), recreate the rbac-go database, migrate/seed/bootstrap, and start rbac-go.
# The database is dropped and recreated each time so seed and bootstrap start clean.
# Set REBUILD=1 to rebuild the image from the rbac-go checkout.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

if [ "${REBUILD:-0}" = 1 ] || ! docker image inspect "$GO_IMAGE" >/dev/null 2>&1; then
  docker build -t "$GO_IMAGE" "$RBAC_GO_DIR"
fi

ensure_loadtest_network
ensure_on_loadtest_network "$PG_CONTAINER"

docker rm -f "$GO_CONTAINER" >/dev/null 2>&1 || true
docker exec "$PG_CONTAINER" psql -U postgres -q \
  -c "DROP DATABASE IF EXISTS rbacgo WITH (FORCE)" -c "CREATE DATABASE rbacgo"

go_run() {
  docker run --rm --network "$LOADTEST_NETWORK" \
    -e "DATABASE_URL=$GO_DATABASE_URL" --entrypoint /usr/local/bin/rbac-go "$GO_IMAGE" "$@"
}
go_run migrate
go_run seed
go_run bootstrap --org "$ORG_ID" --account "$ACCOUNT" --users "$USERS_CSV"

docker run -d --name "$GO_CONTAINER" --network "$LOADTEST_NETWORK" \
  -p "$GO_PORT:8080" -e "DATABASE_URL=$GO_DATABASE_URL" \
  "$GO_IMAGE" >/dev/null

if ! wait_until 60 "rbac-go" probe_app "$GO_PORT" "$GO_PREFIX"; then
  docker logs --tail 40 "$GO_CONTAINER" >&2
  exit 1
fi
echo "rbac-go up on :$GO_PORT (network $LOADTEST_NETWORK → $PG_NET_HOST:$PG_NET_PORT)"
