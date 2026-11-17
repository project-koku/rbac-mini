# Native Go FIPS (operator image)

When Cost Management embeds this binary in the
[koku-service-operator](https://github.com/project-koku/koku-service-operator)
image (`backend: go`), the release build uses the same Red Hat Go toolchain
contract as the operator `manager` / `wait-for` helpers:

- `GOFIPS140=v1.0.0`, `CGO_ENABLED=0`, `-tags=no_openssl,nativefips`
- `GOEXPERIMENT=strictfipsruntime`, `GOTOOLCHAIN=local`
- `cmd/rbac-go/fips.go` (`//go:build nativefips` + `//go:debug fips140=auto`)
- `--fips-status` prints `{"enabled":…,"version":…}` JSON for
  `make verify-fips` in the operator repo

Ordinary `make build` / `make test-sqlite` omit `nativefips` and work with
upstream Go. Those binaries are not the release FIPS artifacts.

`go 1.26.5` in [go.mod](../go.mod) matches the operator's UBI go-toolset so
the Mini binary can be built inside the operator Dockerfile without a second
toolchain. See the operator's
[fips.md](https://github.com/project-koku/koku-service-operator/blob/main/docs/development/fips.md).
