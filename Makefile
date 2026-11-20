.PHONY: test test-sqlite test-postgres test-cover build vet fmt lint govulncheck validate-spec

# Scratch Postgres for test-postgres (override to point elsewhere):
#   initdb -D /tmp/rbac-pg/data -E UTF8 --auth=trust
#   pg_ctl -D /tmp/rbac-pg/data -o "-p 55432 -c listen_addresses='127.0.0.1'" -l /tmp/rbac-pg/log start
#   psql -h 127.0.0.1 -p 55432 -d postgres -c "CREATE DATABASE rbac_test;"
RBAC_TEST_POSTGRES ?= postgres://martinpovolny@127.0.0.1:55432/rbac_test?sslmode=disable

# Product coverage excludes internal/testdb (test harness). Override with
# COVERAGE_THRESHOLD=95 make test-cover once the suite is ready.
COVERAGE_THRESHOLD ?= 90

test: test-sqlite

test-sqlite:
	go test ./... -count=1

# -p 1 serializes packages against the shared scratch instance.
test-postgres:
	RBAC_TEST_POSTGRES='$(RBAC_TEST_POSTGRES)' go test ./... -count=1 -p 1

build:
	go build ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

lint:
	go vet ./...
	golangci-lint run ./...

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

test-cover:
	COVERAGE_THRESHOLD='$(COVERAGE_THRESHOLD)' bash scripts/coverage.sh

validate-spec:
	python3 -c "from openapi_spec_validator import validate; import json; validate(json.load(open('doc/openapi.v1-subset.json'))); print('openapi valid')"
