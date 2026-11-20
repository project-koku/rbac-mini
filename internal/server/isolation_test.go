package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rbac-go/internal/testdb"
)

// seedTwoOrgs creates org 100001 (fixture) and org 200002 with its own
// principal, group, role, and grant so cross-tenant leaks are detectable.
func seedTwoOrgs(t *testing.T) (*Server, string, string, string, string) {
	t.Helper()
	db := testdb.Open(t)
	seedAccess(t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants(org_id, tenant_name, account_id, ready) VALUES('200002','acct2222222','2222222',1)`)
	exec(`INSERT INTO principals(uuid, username, tenant_id) VALUES('pu-b','other_user',
		(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO groups(uuid, name, created, modified, tenant_id) VALUES('g-b','groupB','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
		(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO group_principals(group_id, principal_id) VALUES(
		(SELECT id FROM groups WHERE uuid='g-b'),
		(SELECT id FROM principals WHERE uuid='pu-b'))`)
	exec(`INSERT INTO roles(uuid, name, created, modified, tenant_id) VALUES('r-b','roleB','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
		(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO permissions(application, resource_type, verb, permission, tenant_id)
		VALUES('secret','*','*','secret:*:*',(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO access(role_id, permission_id, tenant_id) VALUES(
		(SELECT id FROM roles WHERE uuid='r-b'),
		(SELECT id FROM permissions WHERE permission='secret:*:*'),
		(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO policies(uuid, name, group_id, tenant_id) VALUES('pol-b','policyB',
		(SELECT id FROM groups WHERE uuid='g-b'),
		(SELECT id FROM tenants WHERE org_id='200002'))`)
	exec(`INSERT INTO policy_roles(policy_id, role_id) VALUES(
		(SELECT id FROM policies WHERE uuid='pol-b'),
		(SELECT id FROM roles WHERE uuid='r-b'))`)

	s := New(db)
	headerA := mint(t, "100001", "test_user", false)
	headerB := mint(t, "200002", "other_user", false)
	return s, headerA, headerB, "g-b", "r-b"
}

func getJSON(t *testing.T, s *Server, header, method, path, body string) (int, []byte) {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

// TestCrossTenantIsolation: org A must never see org B roles/groups/principals
// or access grants, including by UUID get.
func TestCrossTenantIsolation(t *testing.T) {
	s, headerA, headerB, groupBUUID, roleBUUID := seedTwoOrgs(t)

	// Lists from org A must not include B's named fixtures.
	code, body := getJSON(t, s, headerA, http.MethodGet, "/api/rbac/v1/roles/?limit=50", "")
	if code != http.StatusOK {
		t.Fatalf("roles A: status = %d", code)
	}
	if strings.Contains(string(body), "roleB") || strings.Contains(string(body), roleBUUID) {
		t.Errorf("org A roles leaked org B: %s", body)
	}

	code, body = getJSON(t, s, headerA, http.MethodGet, "/api/rbac/v1/groups/?limit=50", "")
	if code != http.StatusOK {
		t.Fatalf("groups A: status = %d", code)
	}
	if strings.Contains(string(body), "groupB") || strings.Contains(string(body), groupBUUID) {
		t.Errorf("org A groups leaked org B: %s", body)
	}

	code, body = getJSON(t, s, headerA, http.MethodGet, "/api/rbac/v1/principals/?limit=50&status=all", "")
	if code != http.StatusOK {
		t.Fatalf("principals A: status = %d", code)
	}
	if strings.Contains(string(body), "other_user") {
		t.Errorf("org A principals leaked org B: %s", body)
	}

	// Direct UUID fetch of B resources as A → 404.
	for _, path := range []string{
		"/api/rbac/v1/groups/" + groupBUUID + "/",
		"/api/rbac/v1/roles/" + roleBUUID + "/",
	} {
		code, _ = getJSON(t, s, headerA, http.MethodGet, path, "")
		if code != http.StatusNotFound {
			t.Errorf("%s as org A: status = %d, want 404", path, code)
		}
	}

	// Access for A must not include B's secret:*:* grant.
	code, body = getJSON(t, s, headerA, http.MethodGet, "/api/rbac/v1/access/?limit=100", "")
	if code != http.StatusOK {
		t.Fatalf("access A: status = %d body %s", code, body)
	}
	if strings.Contains(string(body), "secret:*:*") {
		t.Errorf("org A access leaked org B permission: %s", body)
	}

	// Sanity: org B still sees its own data.
	code, body = getJSON(t, s, headerB, http.MethodGet, "/api/rbac/v1/access/?application=secret&limit=20", "")
	if code != http.StatusOK {
		t.Fatalf("access B: status = %d", code)
	}
	var access struct {
		Data []struct {
			Permission string `json:"permission"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &access); err != nil {
		t.Fatal(err)
	}
	if len(access.Data) != 1 || access.Data[0].Permission != "secret:*:*" {
		t.Errorf("org B access = %+v, want [secret:*:*]", access.Data)
	}

	code, body = getJSON(t, s, headerB, http.MethodGet, "/api/rbac/v1/groups/"+groupBUUID+"/", "")
	if code != http.StatusOK {
		t.Fatalf("group B detail: status = %d body %s", code, body)
	}
	if !strings.Contains(string(body), "groupB") {
		t.Errorf("org B group detail missing groupB: %s", body)
	}
}

// TestCrossTenantWriteMutationsRejected: DELETE/PUT/POST against another
// org's UUIDs (or attaching their role to a local group) must not mutate or
// link across tenants — the usual production leak path beyond list/GET.
func TestCrossTenantWriteMutationsRejected(t *testing.T) {
	s, headerA, headerB, groupBUUID, roleBUUID := seedTwoOrgs(t)
	groupA := "g-a"

	mustReject := func(name, method, path, body string) {
		t.Helper()
		code, resp := getJSON(t, s, headerA, method, path, body)
		if code == http.StatusOK || code == http.StatusCreated || code == http.StatusNoContent {
			t.Errorf("%s: status = %d (body %s), want rejection not success", name, code, resp)
		}
	}

	mustReject("delete group B", http.MethodDelete, "/api/rbac/v1/groups/"+groupBUUID+"/", "")
	mustReject("put group B", http.MethodPut, "/api/rbac/v1/groups/"+groupBUUID+"/",
		`{"name":"hijacked","description":"x"}`)
	mustReject("add members to group B", http.MethodPost,
		"/api/rbac/v1/groups/"+groupBUUID+"/principals/",
		`{"usernames":["test_user"]}`)
	mustReject("delete role B", http.MethodDelete, "/api/rbac/v1/roles/"+roleBUUID+"/", "")
	mustReject("put role B", http.MethodPut, "/api/rbac/v1/roles/"+roleBUUID+"/",
		`{"name":"roleB","display_name":"roleB","description":"","access":[]}`)
	// Attaching another tenant's role UUID to a local group must not succeed.
	mustReject("assign role B to group A", http.MethodPost,
		"/api/rbac/v1/groups/"+groupA+"/roles/",
		`{"roles":["`+roleBUUID+`"]}`)

	// Org B fixtures must still be intact after the rejected writes.
	code, body := getJSON(t, s, headerB, http.MethodGet, "/api/rbac/v1/groups/"+groupBUUID+"/", "")
	if code != http.StatusOK || !strings.Contains(string(body), "groupB") {
		t.Fatalf("group B after rejected writes: status=%d body=%s", code, body)
	}
	code, body = getJSON(t, s, headerB, http.MethodGet, "/api/rbac/v1/roles/"+roleBUUID+"/", "")
	if code != http.StatusOK || !strings.Contains(string(body), "roleB") {
		t.Fatalf("role B after rejected writes: status=%d body=%s", code, body)
	}
	code, body = getJSON(t, s, headerB, http.MethodGet,
		"/api/rbac/v1/access/?application=secret&limit=20", "")
	if code != http.StatusOK || !strings.Contains(string(body), "secret:*:*") {
		t.Fatalf("org B access after rejected writes: status=%d body=%s", code, body)
	}

	// Local group A must not have gained role B via a cross-tenant link.
	code, body = getJSON(t, s, headerA, http.MethodGet,
		"/api/rbac/v1/groups/"+groupA+"/roles/?limit=50", "")
	if code != http.StatusOK {
		t.Fatalf("group A roles: status = %d", code)
	}
	if strings.Contains(string(body), roleBUUID) || strings.Contains(string(body), "roleB") {
		t.Errorf("group A gained org B role after rejected assign: %s", body)
	}
}
