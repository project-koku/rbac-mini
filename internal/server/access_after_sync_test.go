package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rbac-go/internal/keycloak"
	"rbac-go/internal/seed"
	"rbac-go/internal/store"
	"rbac-go/internal/testdb"
)

// seedPlatformDefault adds the public "Default access" platform_default group
// with a single cost-management:settings:read grant (Seed only wires
// admin_default today).
func seedPlatformDefault(t *testing.T, db *store.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("platform default seed %q: %v", q, err)
		}
	}
	pub := `(SELECT id FROM tenants WHERE tenant_name='public')`
	exec(`INSERT INTO roles(uuid, name, system, platform_default, created, modified, tenant_id)
		VALUES('r-viewer','Platform Viewer',1,1,?,?,`+pub+`)`, store.Now(), store.Now())
	exec(`INSERT INTO access(role_id, permission_id, tenant_id) VALUES(
		(SELECT id FROM roles WHERE uuid='r-viewer'),
		(SELECT id FROM permissions WHERE permission='cost-management:settings:read' AND tenant_id=`+pub+`),
		`+pub+`)`)
	exec(`INSERT INTO groups(uuid, name, platform_default, system, created, modified, tenant_id)
		VALUES('g-pd','Default access',1,1,?,?,`+pub+`)`, store.Now(), store.Now())
	exec(`INSERT INTO policies(uuid, name, group_id, tenant_id) VALUES('pol-pd','Default access Policy',
		(SELECT id FROM groups WHERE uuid='g-pd'),` + pub + `)`)
	exec(`INSERT INTO policy_roles(policy_id, role_id) VALUES(
		(SELECT id FROM policies WHERE uuid='pol-pd'),
		(SELECT id FROM roles WHERE uuid='r-viewer'))`)
}

// stubSyncKeycloak returns a Keycloak stub with realm users + org-admin members.
func stubSyncKeycloak(t *testing.T, users []map[string]any, admins []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/onprem/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token"})
	})
	mux.HandleFunc("/admin/realms/onprem/users", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(users)
	})
	mux.HandleFunc("/admin/realms/onprem/roles/org-admin/users", func(w http.ResponseWriter, r *http.Request) {
		out := make([]map[string]any, 0, len(admins))
		for _, name := range admins {
			out = append(out, map[string]any{"username": name})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	return httptest.NewServer(mux)
}

func accessPermissions(t *testing.T, s *Server, header, application string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/rbac/v1/access/?application="+application+"&limit=100", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("access: status = %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data []struct {
			Permission string `json:"permission"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(body.Data))
	for _, d := range body.Data {
		out = append(out, d.Permission)
	}
	return out
}

// TestAccessAfterSync: Keycloak Sync persists principals; GET /access/ then
// reflects platform-default for everyone and admin-default only for org admins
// (identity is_org_admin), without requiring an explicit tenant group.
func TestAccessAfterSync(t *testing.T) {
	db := testdb.Open(t)
	if err := seed.Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	seedPlatformDefault(t, db)

	enabled := true
	users := []map[string]any{
		{"id": "kc-alice", "username": "alice", "enabled": enabled},
		{"id": "kc-bob", "username": "bob", "enabled": enabled},
	}
	srv := stubSyncKeycloak(t, users, []string{"alice"})
	defer srv.Close()

	if err := keycloak.Sync(db, keycloak.Config{
		BaseURL: srv.URL, Realm: "onprem",
		ClientID: "rbac-keycloak-sync", ClientSecret: "s3cret",
		OrgID: "100001", PruneOrphans: true,
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Principals must exist after sync (request path reads DB only).
	for _, u := range []string{"alice", "bob"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM principals pr
			JOIN tenants t ON t.id = pr.tenant_id
			WHERE t.org_id='100001' AND pr.username=?`, u).Scan(&n); err != nil || n != 1 {
			t.Fatalf("principal %s after sync: count=%d err=%v", u, n, err)
		}
	}

	s := New(db)
	adminHeader := mint(t, "100001", "alice", true)
	userHeader := mint(t, "100001", "bob", false)

	adminPerms := accessPermissions(t, s, adminHeader, "cost-management")
	hasAdmin := false
	hasPlatform := false
	for _, p := range adminPerms {
		if p == "cost-management:*:*" {
			hasAdmin = true
		}
		if p == "cost-management:settings:read" {
			hasPlatform = true
		}
	}
	if !hasAdmin {
		t.Errorf("org-admin access missing admin_default grant cost-management:*:*: %v", adminPerms)
	}
	if !hasPlatform {
		t.Errorf("org-admin access missing platform_default grant: %v", adminPerms)
	}

	userPerms := accessPermissions(t, s, userHeader, "cost-management")
	for _, p := range userPerms {
		if p == "cost-management:*:*" {
			t.Errorf("non-admin saw admin_default grant: %v", userPerms)
		}
	}
	foundPlatform := false
	for _, p := range userPerms {
		if p == "cost-management:settings:read" {
			foundPlatform = true
		}
	}
	if !foundPlatform {
		t.Errorf("non-admin missing platform_default grant: %v", userPerms)
	}
}
