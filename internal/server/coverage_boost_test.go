package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRolesListNextPresent hits linkURLOrNil(present=true) when another page exists.
func TestRolesListNextPresent(t *testing.T) {
	s, header := testServerSeeded(t)
	t.Setenv("ROLE_CREATE_ALLOW_LIST", "cost-management")
	for i := 0; i < 3; i++ {
		_ = createRole(t, s, header, fmt.Sprintf("pageRole%d", i), "cost-management:aws.account:read")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/rbac/v1/roles/?limit=1&offset=0", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, `"next":null`) || strings.Contains(body, `"next": null`) {
		t.Fatalf("want non-null next on first page, got %s", body)
	}
	if !strings.Contains(body, `"next":`) {
		t.Fatalf("missing next link in %s", body)
	}
}

// TestAccessPreviousLink hits the access pagination previous branch (offset > 0).
func TestAccessPreviousLink(t *testing.T) {
	s, header := testServerSeeded(t)
	if _, err := s.db.Exec(`INSERT INTO permissions(application, resource_type, verb, permission, tenant_id)
		VALUES('app','b','read','app:b:read',(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO access(role_id, permission_id, tenant_id) VALUES(
		(SELECT id FROM roles WHERE uuid='r-a'),
		(SELECT id FROM permissions WHERE permission='app:b:read'),
		(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/api/rbac/v1/access/?application=app&limit=1&offset=1", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Links map[string]*string `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	prev := body.Links["previous"]
	if prev == nil || !strings.Contains(*prev, "offset=0") {
		t.Fatalf("want previous → offset=0, got %v (body %s)", prev, rec.Body.String())
	}
}

// TestAssignRolesCreatesPolicy: a freshly created group has no policy;
// POST /roles/ must create one via ensureGroupPolicy (ErrNoRows path).
func TestAssignRolesCreatesPolicy(t *testing.T) {
	s, header := testServerSeeded(t)
	gUUID := createGroup(t, s, header, "needs-policy")
	roleUUID := createRole(t, s, header, "policyRole", "cost-management:aws.account:read")

	req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/"+gUUID+"/roles/",
		strings.NewReader(`{"roles":["`+roleUUID+`"]}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign: status = %d body %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM policies WHERE group_id =
		(SELECT id FROM groups WHERE uuid=?)`, gUUID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("policy count = %d err=%v, want 1", n, err)
	}
}

// TestGroupUpdateMissingWithDescriptionOnly: name omitted → Get current;
// unknown UUID maps through groupWriteError → 404.
func TestGroupUpdateMissingWithDescriptionOnly(t *testing.T) {
	s, header := testServerSeeded(t)
	missing := "00000000-0000-4000-8000-0000000000ee"
	req := httptest.NewRequest(http.MethodPut, "/api/rbac/v1/groups/"+missing+"/",
		strings.NewReader(`{"description":"x"}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestClosedDBUnexpectedErrors hits roleWriteError/groupWriteError 500
// branches when the store is closed mid-request.
func TestClosedDBUnexpectedErrors(t *testing.T) {
	s, header := testServerSeeded(t)
	t.Setenv("ROLE_CREATE_ALLOW_LIST", "cost-management")
	_ = s.db.Close()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"access", http.MethodGet, "/api/rbac/v1/access/?application=app", ""},
		{"roles list", http.MethodGet, "/api/rbac/v1/roles/?limit=10", ""},
		{"role create", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"x","access":[{"permission":"cost-management:aws.account:read","resourceDefinitions":[]}]}`},
		{"groups list", http.MethodGet, "/api/rbac/v1/groups/?limit=10", ""},
		{"group create", http.MethodPost, "/api/rbac/v1/groups/", `{"name":"closed-db"}`},
		{"permissions", http.MethodGet, "/api/rbac/v1/permissions/?limit=10", ""},
		{"perm options", http.MethodGet, "/api/rbac/v1/permissions/options/?field=application", ""},
		{"principals", http.MethodGet, "/api/rbac/v1/principals/?status=all&limit=10", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != "" {
				req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}
			req.Header.Set("X-Rh-Identity", header)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestPermissionFilterSplitNonEmpty exercises application/resource_type/verb
// query splitting in permissionFilter.
func TestPermissionFilterSplitNonEmpty(t *testing.T) {
	s, header := testServerSeeded(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/rbac/v1/permissions/?application=cost-management,app&resource_type=aws.account&verb=read&limit=10", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
}
