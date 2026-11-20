#!/usr/bin/env bash
# Measure statement coverage for product packages only.
# Excludes internal/testdb (test harness) and anything outside cmd/+internal/.
# scripts/loadtest is not a Go package in this module.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

THRESHOLD="${COVERAGE_THRESHOLD:-90}"
PROFILE="${COVERPROFILE:-coverage.out}"

COVERPKG="$(go list ./cmd/... ./internal/... | grep -v '/internal/testdb$' | paste -sd, -)"

go test -race -count=1 -timeout 300s \
  -coverprofile="$PROFILE" \
  -coverpkg="$COVERPKG" \
  ./...

total="$(go tool cover -func="$PROFILE" | awk '/^total:/ { gsub(/%/,"",$NF); print $NF }')"
echo "Product coverage: ${total}% (threshold: ${THRESHOLD}%; coverpkg excludes internal/testdb)"
python3 -c "import sys; t=float(sys.argv[1]); th=float(sys.argv[2]); sys.exit(0 if t >= th else 1)" "$total" "$THRESHOLD" \
  || { echo "Coverage ${total}% is below ${THRESHOLD}% threshold" >&2; exit 1; }
