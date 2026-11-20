package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandlerUnauthorizedAndBadParams hits the common writeError branches
// (missing identity, invalid limit/offset/field) across list/mutate handlers
// that were under-covered relative to happy-path tests.
func TestHandlerUnauthorizedAndBadParams(t *testing.T) {
	s, header := testServerSeeded(t)
	groupUUID := groupUUID(t, s, header, "groupA")
	roleUUID := createRole(t, s, header, "edgeRole", "cost-management:aws.account:read")

	type tc struct {
		name   string
		method string
		path   string
		body   string
		header string // empty → omit identity
		want   int
	}
	cases := []tc{
		// Unauthorized (no identity) on several handlers.
		{"access no id", http.MethodGet, "/api/rbac/v1/access/?application=app", "", "", http.StatusUnauthorized},
		{"principals no id", http.MethodGet, "/api/rbac/v1/principals/", "", "", http.StatusUnauthorized},
		{"permissions no id", http.MethodGet, "/api/rbac/v1/permissions/", "", "", http.StatusUnauthorized},
		{"perm options no id", http.MethodGet, "/api/rbac/v1/permissions/options/", "", "", http.StatusUnauthorized},
		{"roles list no id", http.MethodGet, "/api/rbac/v1/roles/", "", "", http.StatusUnauthorized},
		{"role create no id", http.MethodPost, "/api/rbac/v1/roles/", `{"name":"x"}`, "", http.StatusUnauthorized},
		{"role detail no id", http.MethodGet, "/api/rbac/v1/roles/"+roleUUID+"/", "", "", http.StatusUnauthorized},
		{"role update no id", http.MethodPut, "/api/rbac/v1/roles/"+roleUUID+"/", `{"name":"x","access":[]}`, "", http.StatusUnauthorized},
		{"role patch no id", http.MethodPatch, "/api/rbac/v1/roles/"+roleUUID+"/", `{"description":"x"}`, "", http.StatusUnauthorized},
		{"role delete no id", http.MethodDelete, "/api/rbac/v1/roles/"+roleUUID+"/", "", "", http.StatusUnauthorized},
		{"role access no id", http.MethodGet, "/api/rbac/v1/roles/"+roleUUID+"/access/", "", "", http.StatusUnauthorized},
		{"groups list no id", http.MethodGet, "/api/rbac/v1/groups/", "", "", http.StatusUnauthorized},
		{"group create no id", http.MethodPost, "/api/rbac/v1/groups/", `{"name":"x"}`, "", http.StatusUnauthorized},
		{"group detail no id", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/", "", "", http.StatusUnauthorized},
		{"group update no id", http.MethodPut, "/api/rbac/v1/groups/"+groupUUID+"/", `{"name":"x"}`, "", http.StatusUnauthorized},
		{"group delete no id", http.MethodDelete, "/api/rbac/v1/groups/"+groupUUID+"/", "", "", http.StatusUnauthorized},
		{"group members no id", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/principals/", "", "", http.StatusUnauthorized},
		{"group add members no id", http.MethodPost, "/api/rbac/v1/groups/"+groupUUID+"/principals/", `{"usernames":["test_user"]}`, "", http.StatusUnauthorized},
		{"group rem members no id", http.MethodDelete, "/api/rbac/v1/groups/"+groupUUID+"/principals/", `{"usernames":["test_user"]}`, "", http.StatusUnauthorized},
		{"group roles no id", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/roles/", "", "", http.StatusUnauthorized},
		{"group assign roles no id", http.MethodPost, "/api/rbac/v1/groups/"+groupUUID+"/roles/", `{"roles":["`+roleUUID+`"]}`, "", http.StatusUnauthorized},
		{"group rem roles no id", http.MethodDelete, "/api/rbac/v1/groups/"+groupUUID+"/roles/?roles="+roleUUID, "", "", http.StatusUnauthorized},

		// Invalid pagination / field on authenticated calls.
		{"access bad limit", http.MethodGet, "/api/rbac/v1/access/?limit=0", "", header, http.StatusBadRequest},
		{"access bad offset", http.MethodGet, "/api/rbac/v1/access/?offset=-1", "", header, http.StatusBadRequest},
		{"roles bad limit", http.MethodGet, "/api/rbac/v1/roles/?limit=9999", "", header, http.StatusBadRequest},
		{"roles bad offset", http.MethodGet, "/api/rbac/v1/roles/?offset=-1", "", header, http.StatusBadRequest},
		{"groups bad limit", http.MethodGet, "/api/rbac/v1/groups/?limit=abc", "", header, http.StatusBadRequest},
		{"group roles bad limit", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/roles/?limit=0", "", header, http.StatusBadRequest},
		{"group roles bad offset", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/roles/?offset=-1", "", header, http.StatusBadRequest},
		{"group members bad limit", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/principals/?limit=0", "", header, http.StatusBadRequest},
		{"group members bad offset", http.MethodGet, "/api/rbac/v1/groups/"+groupUUID+"/principals/?offset=-1", "", header, http.StatusBadRequest},
		{"permissions bad limit", http.MethodGet, "/api/rbac/v1/permissions/?limit=0", "", header, http.StatusBadRequest},
		{"permissions bad offset", http.MethodGet, "/api/rbac/v1/permissions/?offset=-1", "", header, http.StatusBadRequest},
		{"perm options bad field", http.MethodGet, "/api/rbac/v1/permissions/options/?field=nope", "", header, http.StatusBadRequest},
		{"role access bad limit", http.MethodGet, "/api/rbac/v1/roles/"+roleUUID+"/access/?limit=0", "", header, http.StatusBadRequest},
		{"role access bad offset", http.MethodGet, "/api/rbac/v1/roles/"+roleUUID+"/access/?offset=-1", "", header, http.StatusBadRequest},

		// Malformed JSON bodies.
		{"role create bad json", http.MethodPost, "/api/rbac/v1/roles/", `{`, header, http.StatusBadRequest},
		{"group create bad json", http.MethodPost, "/api/rbac/v1/groups/", `{`, header, http.StatusBadRequest},
		{"group update bad json", http.MethodPut, "/api/rbac/v1/groups/"+groupUUID+"/", `{`, header, http.StatusBadRequest},
		{"group add members bad json", http.MethodPost, "/api/rbac/v1/groups/"+groupUUID+"/principals/", `{`, header, http.StatusBadRequest},
		{"group rem members bad json", http.MethodDelete, "/api/rbac/v1/groups/"+groupUUID+"/principals/", `{`, header, http.StatusBadRequest},
		{"group assign roles bad json", http.MethodPost, "/api/rbac/v1/groups/"+groupUUID+"/roles/", `{`, header, http.StatusBadRequest},
		{"role update bad json", http.MethodPut, "/api/rbac/v1/roles/"+roleUUID+"/", `{`, header, http.StatusBadRequest},
		{"role patch bad json", http.MethodPatch, "/api/rbac/v1/roles/"+roleUUID+"/", `{`, header, http.StatusBadRequest},
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
			if tc.header != "" {
				req.Header.Set("X-Rh-Identity", tc.header)
			}
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestAccessOrderByUsesParts exercises handleAccess sorting via parts().
// sort.SliceStable only invokes the comparator when there are ≥2 entries.
func TestAccessOrderByUsesParts(t *testing.T) {
	s, header := testServerSeeded(t)
	// Second grant so parts() runs inside the order_by comparator.
	if _, err := s.db.Exec(`INSERT INTO permissions(application, resource_type, verb, permission, tenant_id)
		VALUES('app','account','read','app:account:read',(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO access(role_id, permission_id, tenant_id) VALUES(
		(SELECT id FROM roles WHERE uuid='r-a'),
		(SELECT id FROM permissions WHERE permission='app:account:read'),
		(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}
	for _, ob := range []string{"application", "-application", "resource_type", "-resource_type", "verb", "-verb"} {
		req := httptest.NewRequest(http.MethodGet,
			"/api/rbac/v1/access/?application=app&limit=100&order_by="+ob, nil)
		req.Header.Set("X-Rh-Identity", header)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("order_by=%s: status = %d body %s", ob, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"permission"`) {
			t.Fatalf("order_by=%s: empty data, want ≥2 grants so parts() runs", ob)
		}
	}
}

// TestPrincipalsPaginationPreviousLink hits ifGE0 via principals links.previous
// for both the clamp-to-zero path (offset < limit) and the positive path.
func TestPrincipalsPaginationPreviousLink(t *testing.T) {
	s, header := testServerSeeded(t)
	cases := []struct {
		q        string
		wantPrev bool // false → JSON null; true → link containing offset=0
	}{
		{"limit=1&offset=0&status=all", false},
		{"limit=1&offset=1&status=all", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/rbac/v1/principals/?"+tc.q, nil)
		req.Header.Set("X-Rh-Identity", header)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d body %s", tc.q, rec.Code, rec.Body.String())
		}
		var body struct {
			Links struct {
				Previous *string `json:"previous"`
			} `json:"links"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decode: %v", tc.q, err)
		}
		if tc.wantPrev {
			if body.Links.Previous == nil || !strings.Contains(*body.Links.Previous, "offset=0") {
				t.Fatalf("%s: want previous → offset=0, got %v", tc.q, body.Links.Previous)
			}
			continue
		}
		if body.Links.Previous != nil {
			t.Fatalf("%s: want previous=null, got %q", tc.q, *body.Links.Previous)
		}
	}
}

// TestRolesListNextNil hits linkURLOrNil(present=false) when the page is the last.
func TestRolesListNextNil(t *testing.T) {
	s, header := testServerSeeded(t)
	req := httptest.NewRequest(http.MethodGet, "/api/rbac/v1/roles/?limit=100&offset=0", nil)
	req.Header.Set("X-Rh-Identity", header)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"next":null`) && !strings.Contains(rec.Body.String(), `"next": null`) {
		t.Fatalf("want next=null on last page, got %s", rec.Body.String())
	}
}

// TestRoleWriteErrorPaths covers roleWriteError branches via HTTP:
// empty name, unknown/invalid permission, app not allowed, duplicate,
// system-protected update/patch, unsupported patch field, missing UUID.
func TestRoleWriteErrorPaths(t *testing.T) {
	s, header := testServerSeeded(t)
	t.Setenv("ROLE_CREATE_ALLOW_LIST", "cost-management")
	uuid := createRole(t, s, header, "roleWriteOk", "cost-management:aws.account:read")

	if _, err := s.db.Exec(`INSERT INTO roles(uuid, name, system, created, modified, tenant_id)
		VALUES('r-sys','System Role',1,'2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
		(SELECT id FROM tenants WHERE org_id='100001'))`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
		substr string
	}{
		{"create empty name", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"","access":[]}`, http.StatusBadRequest, "required"},
		{"create bad permission", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"badPerm","access":[{"permission":"not-a-perm","resourceDefinitions":[]}]}`,
			http.StatusBadRequest, "Permission does not exist"},
		{"create unknown permission", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"unkPerm","access":[{"permission":"cost-management:nope:read","resourceDefinitions":[]}]}`,
			http.StatusBadRequest, "Permission does not exist"},
		{"create app not allowed", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"wrongApp","access":[{"permission":"sources:*:*","resourceDefinitions":[]}]}`,
			http.StatusBadRequest, "Custom roles cannot be created"},
		{"create duplicate", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"roleWriteOk","access":[{"permission":"cost-management:aws.account:read","resourceDefinitions":[]}]}`,
			http.StatusBadRequest, "already exists"},
		{"create with resourceDefinitions", http.MethodPost, "/api/rbac/v1/roles/",
			`{"name":"roleWithRD","access":[{"permission":"cost-management:aws.account:read","resourceDefinitions":[{"attributeFilter":{"key":"k","operation":"equal","value":"v"}}]}]}`,
			http.StatusCreated, `"uuid"`},
		{"update missing", http.MethodPut, "/api/rbac/v1/roles/00000000-0000-4000-8000-0000000000cc/",
			`{"name":"x","access":[]}`, http.StatusNotFound, "not found"},
		{"update system", http.MethodPut, "/api/rbac/v1/roles/r-sys/",
			`{"name":"System Role","access":[]}`, http.StatusBadRequest, "System roles cannot be modified"},
		{"patch missing", http.MethodPatch, "/api/rbac/v1/roles/00000000-0000-4000-8000-0000000000dd/",
			`{"description":"x"}`, http.StatusNotFound, "not found"},
		{"patch unsupported field", http.MethodPatch, "/api/rbac/v1/roles/" + uuid + "/",
			`{"bogus":"x"}`, http.StatusBadRequest, "not supported"},
		{"patch system", http.MethodPatch, "/api/rbac/v1/roles/r-sys/",
			`{"description":"nope"}`, http.StatusBadRequest, "System roles cannot be modified"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Rh-Identity", header)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.substr != "" && !strings.Contains(rec.Body.String(), tc.substr) {
				t.Fatalf("body = %s, want substring %q", rec.Body.String(), tc.substr)
			}
		})
	}
}

// TestGroupWriteValidationAndDuplicateUpdate covers group Create/Update
// validation and mapUnique (rename onto an existing name → ErrDuplicate).
func TestGroupWriteValidationAndDuplicateUpdate(t *testing.T) {
	s, header := testServerSeeded(t)
	a := groupUUID(t, s, header, "groupA")
	b := createGroup(t, s, header, "groupB")

	longName := strings.Repeat("x", 151)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
		substr string
	}{
		{"create empty", http.MethodPost, "/api/rbac/v1/groups/",
			`{"name":""}`, http.StatusBadRequest, "required"},
		{"create long", http.MethodPost, "/api/rbac/v1/groups/",
			`{"name":"` + longName + `"}`, http.StatusBadRequest, "too long"},
		{"create reserved", http.MethodPost, "/api/rbac/v1/groups/",
			`{"name":"Default access"}`, http.StatusBadRequest, "reserved"},
		{"create nothing", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{}`, http.StatusBadRequest, "nothing to update"},
		{"update empty", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{"name":""}`, http.StatusBadRequest, "required"},
		{"update long", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{"name":"` + longName + `"}`, http.StatusBadRequest, "too long"},
		{"update reserved", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{"name":"Custom default access"}`, http.StatusBadRequest, "reserved"},
		{"update duplicate", http.MethodPut, "/api/rbac/v1/groups/" + b + "/",
			`{"name":"groupA"}`, http.StatusBadRequest, "already exists"},
		{"update description only", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{"description":"updated desc"}`, http.StatusOK, `"groupA"`},
		{"update name+desc", http.MethodPut, "/api/rbac/v1/groups/" + a + "/",
			`{"name":"groupA","description":"again"}`, http.StatusOK, `"groupA"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Rh-Identity", header)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.substr != "" && !strings.Contains(rec.Body.String(), tc.substr) {
				t.Fatalf("body = %s, want substring %q", rec.Body.String(), tc.substr)
			}
		})
	}
}
