package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGroupRolesUnknownRole: POST/DELETE with a role UUID that does not exist
// maps through groupRolesWriteError → 400 (ErrUnknownRole).
func TestGroupRolesUnknownRole(t *testing.T) {
	s, header := testServerSeeded(t)
	groupUUID := groupUUID(t, s, header, "groupA")
	ghost := "00000000-0000-4000-8000-000000000099"

	req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/"+groupUUID+"/roles/",
		strings.NewReader(`{"roles":["`+ghost+`"]}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("assign unknown role: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("assign body = %s, want not found", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete,
		"/api/rbac/v1/groups/"+groupUUID+"/roles/?roles="+ghost, nil)
	req.Header.Set("X-Rh-Identity", header)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("remove unknown role: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestGroupRolesAdminDefaultProtected: role assign/remove on admin_default
// groups is rejected with 400 "cannot be modified".
func TestGroupRolesAdminDefaultProtected(t *testing.T) {
	s, header := testServerSeeded(t)
	if _, err := s.db.Exec(`INSERT INTO groups(uuid, name, admin_default, tenant_id) VALUES('g-ad','Admin default',1,
		(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	roleUUID := createRole(t, s, header, "roleForAd", "cost-management:aws.account:read")

	req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/g-ad/roles/",
		strings.NewReader(`{"roles":["`+roleUUID+`"]}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cannot be modified") {
		t.Fatalf("assign admin_default: status = %d body %s, want 400 + cannot be modified",
			rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete,
		"/api/rbac/v1/groups/g-ad/roles/?roles="+roleUUID, nil)
	req.Header.Set("X-Rh-Identity", header)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cannot be modified") {
		t.Fatalf("remove admin_default: status = %d body %s, want 400 + cannot be modified",
			rec.Code, rec.Body.String())
	}
}

// TestGroupRolesPlatformDefaultProtected: role assign/remove on
// platform_default groups must be rejected like Django's protect_special_groups.
func TestGroupRolesPlatformDefaultProtected(t *testing.T) {
	s, header := testServerSeeded(t)
	if _, err := s.db.Exec(`INSERT INTO groups(uuid, name, platform_default, tenant_id) VALUES('g-pd','Default access',1,
		(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	roleUUID := createRole(t, s, header, "roleForPd", "cost-management:aws.account:read")

	req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/g-pd/roles/",
		strings.NewReader(`{"roles":["`+roleUUID+`"]}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("assign platform_default: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	} else if !strings.Contains(rec.Body.String(), "cannot be modified") &&
		!strings.Contains(rec.Body.String(), "platform_default") {
		t.Errorf("assign body = %s, want protect wording", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete,
		"/api/rbac/v1/groups/g-pd/roles/?roles="+roleUUID, nil)
	req.Header.Set("X-Rh-Identity", header)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("remove platform_default: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestGroupRolesMissingGroup: assign/remove/list against an unknown group UUID → 404.
func TestGroupRolesMissingGroup(t *testing.T) {
	s, header := testServerSeeded(t)
	missing := "00000000-0000-4000-8000-0000000000aa"
	roleUUID := createRole(t, s, header, "roleOrphan", "cost-management:aws.account:read")

	req := httptest.NewRequest(http.MethodPost, "/api/rbac/v1/groups/"+missing+"/roles/",
		strings.NewReader(`{"roles":["`+roleUUID+`"]}`))
	req.Header.Set("X-Rh-Identity", header)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("assign missing group: status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete,
		"/api/rbac/v1/groups/"+missing+"/roles/?roles="+roleUUID, nil)
	req.Header.Set("X-Rh-Identity", header)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("remove missing group: status = %d, want 404", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/rbac/v1/groups/"+missing+"/roles/?limit=10", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list roles missing group: status = %d, want 404", rec.Code)
	}
}

// TestMissingGroupAndRoleDetail: GET detail for unknown UUIDs → 404.
func TestMissingGroupAndRoleDetail(t *testing.T) {
	s, header := testServerSeeded(t)
	missing := "00000000-0000-4000-8000-0000000000bb"
	for _, path := range []string{
		"/api/rbac/v1/groups/" + missing + "/",
		"/api/rbac/v1/roles/" + missing + "/",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Rh-Identity", header)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 (body: %s)", path, rec.Code, rec.Body.String())
		}
	}
}

// TestGroupRolesWriteErrorSkipsUnexpected500 documents that the unexpected
// 500 branch of groupRolesWriteError is not reachable without injecting a
// store/driver failure; no production change is allowed here to force it.
func TestGroupRolesWriteErrorSkipsUnexpected500(t *testing.T) {
	t.Skip("500/unexpected path in groupRolesWriteError requires a broken DB/driver; cannot trigger without production changes")
}
