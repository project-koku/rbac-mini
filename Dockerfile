# rbac-go: minimal on-prem RBAC v1 (replaces insights-rbac where only
# koku + koku-service-operator need it). UBI-based like the operator images;
# ubi-minimal (not ubi-micro) so the shell entrypoint below can run.
FROM registry.access.redhat.com/ubi9/go-toolset:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# ubi9/go-toolset runs as non-root; write under WORKDIR (not /out).
RUN CGO_ENABLED=0 go build -trimpath -o /src/rbac-go ./cmd/rbac-go

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.5
WORKDIR /data
COPY --from=build /src/rbac-go /usr/local/bin/rbac-go
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve", "--addr", ":8080"]
