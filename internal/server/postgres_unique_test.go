package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// requirePostgres skips unless RBAC_TEST_POSTGRES is set (same gate as testdb).
func requirePostgres(t *testing.T) {
	t.Helper()
	if os.Getenv("RBAC_TEST_POSTGRES") == "" {
		t.Skip("RBAC_TEST_POSTGRES unset; skipping Postgres unique-violation mapping")
	}
}

// TestPostgresDuplicateGroupCreateMaps400: under real Postgres, a second
// INSERT hitting UNIQUE(name, tenant_id) must surface as HTTP 400 (not 500).
func TestPostgresDuplicateGroupCreateMaps400(t *testing.T) {
	requirePostgres(t)
	s, header := testServerSeeded(t)

	create := func(name string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/",
			strings.NewReader(`{"name":"`+name+`"}`))
		req.Header.Set("X-Rh-Identity", header)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := create("pg-dup-group"); code != http.StatusCreated {
		t.Fatalf("first create: status = %d body %s, want 201", code, body)
	}
	code, body := create("pg-dup-group")
	if code != http.StatusBadRequest {
		t.Fatalf("duplicate group: status = %d body %s, want 400 (unique → ErrDuplicate)", code, body)
	}
	if !strings.Contains(body, "already exists") {
		t.Errorf("duplicate body = %s, want already exists", body)
	}
}

// TestPostgresDuplicateRoleCreateMaps400: duplicate role name under Postgres
// must map to 400 via roleWriteError ("already exists"), not 500.
func TestPostgresDuplicateRoleCreateMaps400(t *testing.T) {
	requirePostgres(t)
	s, header := testServerSeeded(t)
	t.Setenv("ROLE_CREATE_ALLOW_LIST", "cost-management")

	create := func(name string) (int, string) {
		t.Helper()
		payload := `{"name":"` + name + `","access":[{"permission":"cost-management:aws.account:read","resourceDefinitions":[]}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/roles/", strings.NewReader(payload))
		req.Header.Set("X-Rh-Identity", header)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := create("pg-dup-role"); code != http.StatusCreated {
		t.Fatalf("first create: status = %d body %s, want 201", code, body)
	}
	code, body := create("pg-dup-role")
	if code != http.StatusBadRequest {
		t.Fatalf("duplicate role: status = %d body %s, want 400", code, body)
	}
	if !strings.Contains(body, "already exists") {
		t.Errorf("duplicate body = %s, want already exists", body)
	}
}
