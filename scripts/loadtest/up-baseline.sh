#!/usr/bin/env bash
# Start the Postgres and Valkey containers that both app baselines use.
# Sets max_connections; Django's gunicorn threads hold persistent connections and
# exhaust the default of 100 (see doc/LOADTEST.md, Finding 3).
# Attaches both to LOADTEST_NETWORK so app containers use container DNS.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

pg_ready() { docker exec "$PG_CONTAINER" pg_isready -U postgres; }
valkey_ready() { [ "$(docker exec "$VALKEY_CONTAINER" valkey-cli ping)" = PONG ]; }

ensure_loadtest_network

if ! docker inspect "$PG_CONTAINER" >/dev/null 2>&1; then
  docker run -d --name "$PG_CONTAINER" --network "$LOADTEST_NETWORK" \
    -e POSTGRES_USER=postgres -e "POSTGRES_PASSWORD=$PG_PASSWORD" \
    -e POSTGRES_DB=postgres -p "$PG_PORT:5432" "$PG_IMAGE" >/dev/null
else
  docker start "$PG_CONTAINER" >/dev/null
  ensure_on_loadtest_network "$PG_CONTAINER"
fi
wait_until 60 "postgres" pg_ready

current="$(docker exec "$PG_CONTAINER" psql -U postgres -tAc 'SHOW max_connections')"
if [ "$current" != "$PG_MAX_CONNECTIONS" ]; then
  # ALTER SYSTEM needs a free connection, so the app containers have to go first.
  docker rm -f "$DJANGO_CONTAINER" "$GO_CONTAINER" >/dev/null 2>&1 || true
  docker exec "$PG_CONTAINER" psql -U postgres -qc "ALTER SYSTEM SET max_connections = $PG_MAX_CONNECTIONS"
  docker restart "$PG_CONTAINER" >/dev/null
  wait_until 60 "postgres after restart" pg_ready
  ensure_on_loadtest_network "$PG_CONTAINER"
fi

if ! docker inspect "$VALKEY_CONTAINER" >/dev/null 2>&1; then
  docker run -d --name "$VALKEY_CONTAINER" --network "$LOADTEST_NETWORK" \
    -p "$VALKEY_PORT:6379" "$VALKEY_IMAGE" >/dev/null
else
  docker start "$VALKEY_CONTAINER" >/dev/null
  ensure_on_loadtest_network "$VALKEY_CONTAINER"
fi
wait_until 60 "valkey" valkey_ready

echo "baseline services up: postgres :$PG_PORT (max_connections=$PG_MAX_CONNECTIONS), valkey :$VALKEY_PORT (network $LOADTEST_NETWORK)"
