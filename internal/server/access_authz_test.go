package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rbac-go/internal/seed"
	"rbac-go/internal/testdb"
)

// TestAccessUsernameOverrideRequiresOrgAdmin: ?username= is an authz
// boundary — org-admins may resolve another principal's ACL; non-admins
// must keep their own (override ignored), never inspect a peer.
func TestAccessUsernameOverrideRequiresOrgAdmin(t *testing.T) {
	db := testdb.Open(t)
	seedAccess(t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	// peer_user: same tenant, no group membership → empty app grants.
	exec(`INSERT INTO principals(uuid, username, tenant_id) VALUES('pu-peer','peer_user',
		(SELECT id FROM tenants WHERE org_id='100001'))`)

	s := New(db)
	userHeader := mint(t, "100001", "test_user", false)
	adminHeader := mint(t, "100001", "test_user", true)
	peerHeader := mint(t, "100001", "peer_user", false)

	perms := func(header, query string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/rbac/v1/access/"+query, nil)
		req.Header.Set("X-Rh-Identity", header)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("access %s: status = %d body %s", query, rec.Code, rec.Body.String())
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

	hasApp := func(list []string) bool {
		for _, p := range list {
			if p == "app:*:*" {
				return true
			}
		}
		return false
	}

	self := perms(userHeader, "?application=app&limit=100")
	if !hasApp(self) {
		t.Fatalf("test_user missing own grant: %v", self)
	}
	peerOwn := perms(peerHeader, "?application=app&limit=100")
	if hasApp(peerOwn) {
		t.Fatalf("peer_user unexpectedly has app:*:*: %v", peerOwn)
	}

	// Non-admin + ?username=peer_user must NOT see peer's empty ACL as a
	// successful override of self — override is ignored, own grants remain.
	nonAdminOverride := perms(userHeader, "?application=app&limit=100&username=peer_user")
	if !hasApp(nonAdminOverride) {
		t.Errorf("non-admin ?username= override stripped caller's grants: %v", nonAdminOverride)
	}

	// Peer calling ?username=test_user must not receive the privileged ACL
	// either (override ignored → peer keeps their own empty app grants).
	peerOverride := perms(peerHeader, "?application=app&limit=100&username=test_user")
	if hasApp(peerOverride) {
		t.Errorf("peer ?username=test_user leaked app:*:*: %v", peerOverride)
	}

	// Org-admin may resolve peer's ACL (empty for app).
	adminOverride := perms(adminHeader, "?application=app&limit=100&username=peer_user")
	if hasApp(adminOverride) {
		t.Errorf("admin ?username=peer_user still saw test_user grant: %v", adminOverride)
	}
}

// TestAccessAdminDefaultFollowsIdentityNotDBFlag: admin_default grants follow
// the identity header's is_org_admin, not principals.is_org_admin — a stale
// DB flag after Keycloak drift must not grant or deny incorrectly.
func TestAccessAdminDefaultFollowsIdentityNotDBFlag(t *testing.T) {
	db := testdb.Open(t)
	if err := seed.Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	seedPlatformDefault(t, db)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants(org_id, tenant_name, account_id, ready) VALUES('100001','acct1111111','1111111',1)`)
	// DB says not admin; identity may still claim admin (and the reverse).
	exec(`INSERT INTO principals(uuid, username, is_org_admin, is_active, tenant_id)
		VALUES('pu-stale','stale_user',0,1,(SELECT id FROM tenants WHERE org_id='100001'))`)
	exec(`INSERT INTO principals(uuid, username, is_org_admin, is_active, tenant_id)
		VALUES('pu-dbadmin','db_admin',1,1,(SELECT id FROM tenants WHERE org_id='100001'))`)

	s := New(db)

	contains := func(perms []string, want string) bool {
		for _, p := range perms {
			if p == want {
				return true
			}
		}
		return false
	}

	// Identity admin=true, DB is_org_admin=0 → must still get admin_default.
	idAdmin := mint(t, "100001", "stale_user", true)
	got := accessPermissions(t, s, idAdmin, "cost-management")
	if !contains(got, "cost-management:*:*") {
		t.Errorf("identity admin / DB non-admin missing admin_default: %v", got)
	}

	// Identity admin=false, DB is_org_admin=1 → must NOT get admin_default.
	idUser := mint(t, "100001", "db_admin", false)
	got = accessPermissions(t, s, idUser, "cost-management")
	if contains(got, "cost-management:*:*") {
		t.Errorf("identity non-admin / DB admin still got admin_default: %v", got)
	}
	// Platform default still applies to everyone.
	if !contains(got, "cost-management:settings:read") {
		t.Errorf("identity non-admin missing platform_default: %v", got)
	}
}
