package seed

import (
	"slices"
	"strings"
	"testing"
	"time"

	"rbac-go/internal/access"
	"rbac-go/internal/store"
	"rbac-go/internal/testdb"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	return testdb.Open(t)
}

func counts(t *testing.T, db *store.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"tenants", "roles", "permissions", "access", "resource_definitions",
		"groups", "policies", "policy_roles"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// TestSeedCostAdministrator: the seed provides the public tenant plus the
// Cost Administrator role granting cost-management:*:*, and running it twice
// changes nothing (operator Job re-runs on every deploy).
func TestSeedCostAdministrator(t *testing.T) {
	db := testDB(t)

	if err := Seed(db); err != nil {
		t.Fatalf("first Seed returned error: %v", err)
	}
	var perm string
	err := db.QueryRow(`SELECT p.permission FROM permissions p
		JOIN access a ON a.permission_id = p.id
		JOIN roles r ON r.id = a.role_id
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name = 'Cost Administrator' AND t.tenant_name = 'public'`).Scan(&perm)
	if err != nil {
		t.Fatalf("Cost Administrator grant missing: %v", err)
	}
	if perm != "cost-management:*:*" {
		t.Errorf("permission = %q, want %q", perm, "cost-management:*:*")
	}
	// On-prem koku also queries ?application=sources, which lives in a
	// different application bucket: the Sources administrator role.
	var sourcesPerm string
	err = db.QueryRow(`SELECT p.permission FROM permissions p
		JOIN access a ON a.permission_id = p.id
		JOIN roles r ON r.id = a.role_id
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name = 'Sources administrator' AND t.tenant_name = 'public'`).Scan(&sourcesPerm)
	if err != nil {
		t.Fatalf("Sources administrator grant missing: %v", err)
	}
	if sourcesPerm != "sources:*:*" {
		t.Errorf("permission = %q, want %q", sourcesPerm, "sources:*:*")
	}

	// The UI role wizard lists the granular catalog (allowed_only,
	// exclude_globals), not just the two application-wide grants.
	var permCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM permissions`).Scan(&permCount); err != nil || permCount < 20 {
		t.Errorf("permissions = %d, err = %v, want the full catalog", permCount, err)
	}
	var modelRead int
	if err := db.QueryRow(`SELECT COUNT(*) FROM permissions
		WHERE permission='cost-management:cost_model:read'`).Scan(&modelRead); err != nil || modelRead != 1 {
		t.Errorf("cost-management:cost_model:read count = %d, err = %v, want 1", modelRead, err)
	}

	// Both roles carry admin_default, and the public "Default admin access"
	// group links them (Django seed_group parity).
	for _, name := range []string{"Cost Administrator", "Sources administrator"} {
		var adminDefault int
		if err := db.QueryRow(`SELECT admin_default FROM roles WHERE name=?`, name).Scan(&adminDefault); err != nil || adminDefault != 1 {
			t.Errorf("role %q admin_default = %d, err = %v, want 1", name, adminDefault, err)
		}
	}
	var adminDefaultGroup int
	if err := db.QueryRow(`SELECT admin_default FROM groups WHERE name='Default admin access'`).Scan(&adminDefaultGroup); err != nil || adminDefaultGroup != 1 {
		t.Fatalf("Default admin access admin_default = %d, err = %v, want 1", adminDefaultGroup, err)
	}
	var linked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		WHERE p.name='Default admin access'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("Default admin access roles = %d, err = %v, want 2", linked, err)
	}
	for _, q := range []string{
		`SELECT created FROM roles WHERE name='Cost Administrator'`,
		`SELECT modified FROM roles WHERE name='Cost Administrator'`,
		`SELECT created FROM groups WHERE name='Default admin access'`,
		`SELECT modified FROM groups WHERE name='Default admin access'`,
	} {
		var modified string
		if err := db.QueryRow(q).Scan(&modified); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if _, err := time.Parse(time.RFC3339, modified); err != nil {
			t.Errorf("%s: modified = %q, not RFC3339: %v", q, modified, err)
		}
	}

	// An org admin with no explicit group gets the admin_default grants; a
	// regular user in the same tenant gets none until someone adds them.
	if _, err := db.Exec(`INSERT INTO tenants(org_id, tenant_name, ready) VALUES('200002','acct',1)`); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO principals(uuid, username, tenant_id)
		SELECT 'pu-viewer', 'viewer', id FROM tenants WHERE org_id='200002'`); err != nil {
		t.Fatalf("principal: %v", err)
	}
	adminAccess, err := access.Query(db, "200002", "viewer", []string{"cost-management"}, true)
	if err != nil {
		t.Fatalf("admin Query: %v", err)
	}
	if len(adminAccess) != 1 || adminAccess[0].Permission != "cost-management:*:*" {
		t.Errorf("org admin access = %v, want [cost-management:*:*]", adminAccess)
	}
	userAccess, err := access.Query(db, "200002", "viewer", []string{"cost-management"}, false)
	if err != nil {
		t.Fatalf("user Query: %v", err)
	}
	if len(userAccess) != 0 {
		t.Errorf("non-admin access = %v, want empty", userAccess)
	}

	first := counts(t, db)

	if err := Seed(db); err != nil {
		t.Fatalf("second Seed returned error: %v", err)
	}
	second := counts(t, db)
	for table, n := range first {
		if second[table] != n {
			t.Errorf("%s: count changed %d -> %d, want idempotent", table, n, second[table])
		}
	}
}

// TestBootstrapGrantsSourcesAdministrator: tenant + "CI Test Admin" carrying
// Sources administrator only (COST-8231). End-to-end: sources write present,
// cost-management admin absent, Admin=false, type=service-account.
func TestBootstrapGrantsSourcesAdministrator(t *testing.T) {
	db := testDB(t)
	if err := Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	users := []string{"cost-mgmt-operator", "admin"}
	if err := Bootstrap(db, "100001", "acct1111111", users); err != nil {
		t.Fatalf("first Bootstrap returned error: %v", err)
	}

	var ready int
	if err := db.QueryRow(`SELECT ready FROM tenants WHERE org_id='100001'`).Scan(&ready); err != nil {
		t.Fatalf("tenant missing: %v", err)
	}
	if ready != 1 {
		t.Errorf("tenant ready = %d, want 1", ready)
	}

	var role string
	err := db.QueryRow(`SELECT r.name FROM policies pol
		JOIN groups g ON g.id = pol.group_id
		JOIN policy_roles pr ON pr.policy_id = pol.id
		JOIN roles r ON r.id = pr.role_id
		JOIN tenants t ON t.id = pol.tenant_id
		WHERE t.org_id='100001' AND g.name='CI Test Admin'`).Scan(&role)
	if err != nil {
		t.Fatalf("CI Test Admin policy missing: %v", err)
	}
	if role != "Sources administrator" {
		t.Errorf("role = %q, want %q", role, "Sources administrator")
	}
	var roleCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policies pol
		JOIN groups g ON g.id = pol.group_id
		JOIN policy_roles pr ON pr.policy_id = pol.id
		JOIN tenants t ON t.id = pol.tenant_id
		WHERE t.org_id='100001' AND g.name='CI Test Admin'`).Scan(&roleCount); err != nil || roleCount != 1 {
		t.Fatalf("CI Test Admin role count = %d err=%v, want 1", roleCount, err)
	}

	for _, u := range users {
		var inGroup int
		err := db.QueryRow(`SELECT COUNT(*) FROM principals pr
			JOIN group_principals gp ON gp.principal_id = pr.id
			JOIN groups g ON g.id = gp.group_id
			JOIN tenants t ON t.id = pr.tenant_id AND t.id = g.tenant_id
			WHERE t.org_id='100001' AND pr.username=? AND g.name='CI Test Admin'`, u).Scan(&inGroup)
		if err != nil || inGroup != 1 {
			t.Errorf("principal %q in group: count=%d, err=%v, want 1", u, inGroup, err)
		}
		var ptype string
		if err := db.QueryRow(`SELECT pr.type FROM principals pr
			JOIN tenants t ON t.id = pr.tenant_id
			WHERE t.org_id='100001' AND pr.username=?`, u).Scan(&ptype); err != nil || ptype != "service-account" {
			t.Errorf("principal %q type = %q err=%v, want service-account", u, ptype, err)
		}
	}

	sources, err := access.Query(db, "100001", "cost-mgmt-operator", []string{"sources"}, false)
	if err != nil {
		t.Fatalf("Query sources: %v", err)
	}
	if len(sources) != 1 || sources[0].Permission != "sources:*:*" {
		t.Errorf("sources access = %v, want [sources:*:*]", sources)
	}
	cost, err := access.Query(db, "100001", "cost-mgmt-operator", []string{"cost-management"}, false)
	if err != nil {
		t.Fatalf("Query cost-management: %v", err)
	}
	if len(cost) != 0 {
		t.Errorf("cost-management access = %v, want empty (no Cost Administrator)", cost)
	}

	before := counts(t, db)
	if err := Bootstrap(db, "100001", "acct1111111", users); err != nil {
		t.Fatalf("second Bootstrap returned error: %v", err)
	}
	after := counts(t, db)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("%s: count changed %d -> %d, want idempotent", table, n, after[table])
		}
	}
}

// TestBootstrapReplacesCostAdministratorBind: re-running bootstrap after an
// older Cost Administrator policy bind leaves Sources administrator only.
func TestBootstrapReplacesCostAdministratorBind(t *testing.T) {
	db := testDB(t)
	if err := Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if err := Bootstrap(db, "100001", "acct", []string{"cost-mgmt-operator"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	var policyID, costRoleID int64
	if err := db.QueryRow(`SELECT pol.id FROM policies pol
		JOIN groups g ON g.id = pol.group_id
		JOIN tenants t ON t.id = pol.tenant_id
		WHERE t.org_id='100001' AND g.name='CI Test Admin'`).Scan(&policyID); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := db.QueryRow(`SELECT r.id FROM roles r
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name='Cost Administrator' AND t.tenant_name='public'`).Scan(&costRoleID); err != nil {
		t.Fatalf("Cost Administrator: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO policy_roles(policy_id, role_id) VALUES(?, ?)`,
		policyID, costRoleID); err != nil {
		t.Fatalf("inject Cost Administrator: %v", err)
	}
	if err := Bootstrap(db, "100001", "acct", []string{"cost-mgmt-operator"}); err != nil {
		t.Fatalf("re-Bootstrap: %v", err)
	}
	var names []string
	rows, err := db.Query(`SELECT r.name FROM policy_roles pr
		JOIN roles r ON r.id = pr.role_id WHERE pr.policy_id=? ORDER BY r.name`, policyID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if len(names) != 1 || names[0] != "Sources administrator" {
		t.Fatalf("policy roles = %v, want [Sources administrator]", names)
	}
}

// TestBootstrapRequiresSeededSourcesAdministrator: bootstrap looks up the
// public Sources administrator role; without Seed it must fail.
func TestBootstrapRequiresSeededSourcesAdministrator(t *testing.T) {
	db := testDB(t)
	if err := Bootstrap(db, "100001", "acct", []string{"alice"}); err == nil {
		t.Fatal("Bootstrap without Seed succeeded, want error")
	}
}

func TestBootstrapErrorsOnClosedDB(t *testing.T) {
	db := testDB(t)
	_ = db.Close()
	if err := Bootstrap(db, "100001", "acct", []string{"cost-mgmt-operator"}); err == nil {
		t.Fatal("Bootstrap on closed DB succeeded, want error")
	}
}

// TestBootstrapUpgradesLegacyUserType: re-bootstrap flips type=user →
// service-account so sync prune cannot remove the CMMO principal.
func TestBootstrapUpgradesLegacyUserType(t *testing.T) {
	db := testDB(t)
	if err := Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if err := Bootstrap(db, "100001", "acct", nil); err != nil {
		t.Fatalf("Bootstrap group: %v", err)
	}
	var tenantID int64
	if err := db.QueryRow(`SELECT id FROM tenants WHERE org_id='100001'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO principals(uuid, username, type, tenant_id)
		VALUES(?, 'cost-mgmt-operator', 'user', ?)`, store.NewUUID(), tenantID); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if err := Bootstrap(db, "100001", "acct", []string{"cost-mgmt-operator"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	var ptype string
	if err := db.QueryRow(`SELECT type FROM principals WHERE username='cost-mgmt-operator' AND tenant_id=?`,
		tenantID).Scan(&ptype); err != nil || ptype != "service-account" {
		t.Fatalf("type = %q err=%v, want service-account", ptype, err)
	}
}

// TestBootstrapLowercasesUsernames: usernames are stored lowercased like
// Django's principal upsert path.
func TestBootstrapLowercasesUsernames(t *testing.T) {
	db := testDB(t)
	if err := Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if err := Bootstrap(db, "100001", "acct", []string{"Alice", "BOB"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM principals pr
		JOIN tenants t ON t.id = pr.tenant_id
		WHERE t.org_id='100001' AND pr.username IN ('alice','bob')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("lowercased principals = %d err=%v, want 2", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM principals pr
		JOIN tenants t ON t.id = pr.tenant_id
		WHERE t.org_id='100001' AND pr.username IN ('Alice','BOB')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mixed-case leftovers = %d, want 0", n)
	}
}

// TestSeedPackagedRoles: operator-parity system roles that are not
// admin_default and must not attach to Default admin access (unlike Cost
// Administrator / Sources administrator). Covers Price List Admin/Viewer and
// Cost OpenShift Viewer in one table-driven check.
func TestSeedPackagedRoles(t *testing.T) {
	db := testDB(t)

	if err := Seed(db); err != nil {
		t.Fatalf("first Seed returned error: %v", err)
	}

	type wantRole struct {
		name        string
		displayName string
		description string
		perms       []string
	}
	want := []wantRole{
		{
			name:        "Cost Price List Administrator",
			displayName: "Cost Price List administrator",
			description: "Perform read and write operations on cost models.",
			perms:       []string{"cost-management:cost_model:*", "cost-management:settings:*"},
		},
		{
			name:        "Cost Price List Viewer",
			displayName: "Cost Price List viewer",
			description: "Perform read operations on cost models.",
			perms:       []string{"cost-management:cost_model:read", "cost-management:settings:read"},
		},
		{
			name:        "Cost OpenShift Viewer",
			displayName: "Cost OpenShift viewer",
			description: "Perform read operations on cost reports related to OpenShift sources.",
			perms:       []string{"cost-management:openshift.cluster:*"},
		},
	}

	roleAccessCounts := map[string]int{}
	for _, r := range want {
		assertPackagedRole(t, db, r.name, r.displayName, r.description, r.perms)
		roleAccessCounts[r.name] = len(r.perms)
	}

	var linked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		JOIN tenants t ON t.id = p.tenant_id
		WHERE p.name='Default admin access' AND t.tenant_name='public'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("Default admin access roles = %d, err = %v, want 2", linked, err)
	}

	if err := Seed(db); err != nil {
		t.Fatalf("second Seed returned error: %v", err)
	}
	for _, r := range want {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM roles r
			JOIN tenants t ON t.id = r.tenant_id
			WHERE r.name=? AND t.tenant_name='public'`, r.name).Scan(&n); err != nil || n != 1 {
			t.Errorf("after re-seed, role %q count = %d, err = %v, want 1", r.name, n, err)
		}
		var accessN int
		if err := db.QueryRow(`SELECT COUNT(*) FROM access a
			JOIN roles r ON r.id = a.role_id
			JOIN tenants t ON t.id = r.tenant_id
			WHERE r.name=? AND t.tenant_name='public'`, r.name).Scan(&accessN); err != nil {
			t.Fatalf("after re-seed, access count for %q: %v", r.name, err)
		}
		if accessN != roleAccessCounts[r.name] {
			t.Errorf("after re-seed, role %q access count = %d, want %d", r.name, accessN, roleAccessCounts[r.name])
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		JOIN tenants t ON t.id = p.tenant_id
		WHERE p.name='Default admin access' AND t.tenant_name='public'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("after re-seed, Default admin access roles = %d, err = %v, want 2", linked, err)
	}
}

func assertPackagedRole(t *testing.T, db *store.DB, name, displayName, description string, perms []string) {
	t.Helper()

	var system, adminDefault, platformDefault int
	var gotDisplay, gotDescription string
	err := db.QueryRow(`SELECT r.system, r.admin_default, r.platform_default, r.display_name, r.description
		FROM roles r
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'`, name).Scan(
		&system, &adminDefault, &platformDefault, &gotDisplay, &gotDescription)
	if err != nil {
		t.Fatalf("role %q missing: %v", name, err)
	}
	if system != 1 {
		t.Errorf("role %q system = %d, want 1", name, system)
	}
	if adminDefault != 0 {
		t.Errorf("role %q admin_default = %d, want 0", name, adminDefault)
	}
	if platformDefault != 0 {
		t.Errorf("role %q platform_default = %d, want 0", name, platformDefault)
	}
	if gotDisplay != displayName {
		t.Errorf("role %q display_name = %q, want %q", name, gotDisplay, displayName)
	}
	if gotDescription != description {
		t.Errorf("role %q description = %q, want %q", name, gotDescription, description)
	}

	rows, err := db.Query(`SELECT p.permission FROM permissions p
		JOIN access a ON a.permission_id = p.id
		JOIN roles r ON r.id = a.role_id
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'
		ORDER BY p.permission`, name)
	if err != nil {
		t.Fatalf("access query for %q: %v", name, err)
	}
	var got []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			t.Fatalf("scan access for %q: %v", name, err)
		}
		got = append(got, perm)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows for %q: %v", name, err)
	}
	_ = rows.Close()
	wantPerms := append([]string(nil), perms...)
	slices.Sort(wantPerms)
	if !slices.Equal(got, wantPerms) {
		t.Errorf("role %q grants = %v, want %v", name, got, wantPerms)
	}

	var onAdminGroup int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		JOIN roles r ON r.id = pr.role_id
		JOIN tenants t ON t.id = p.tenant_id
		WHERE p.name='Default admin access' AND t.tenant_name='public' AND r.name=?`, name).Scan(&onAdminGroup); err != nil {
		t.Fatalf("Default admin access link check for %q: %v", name, err)
	}
	if onAdminGroup != 0 {
		t.Errorf("role %q linked to Default admin access, want not linked", name)
	}
}

// TestSeedDoesNotCreateUnexpectedRoles: Mini must not seed Cost Cloud Viewer
// or Django platform junk (Notifications, Approval, Inventory, OCM, User
// Access, Local Test).
func TestSeedDoesNotCreateUnexpectedRoles(t *testing.T) {
	db := testDB(t)

	if err := Seed(db); err != nil {
		t.Fatalf("Seed returned error: %v", err)
	}

	exactDenylist := []string{
		"Cost Cloud Viewer",
	}
	for _, name := range exactDenylist {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM roles r
			JOIN tenants t ON t.id = r.tenant_id
			WHERE r.name=? AND t.tenant_name='public'`, name).Scan(&n); err != nil {
			t.Fatalf("denylist exact check for %q: %v", name, err)
		}
		if n != 0 {
			t.Errorf("unexpected role %q seeded (count=%d)", name, n)
		}
	}

	rows, err := db.Query(`SELECT r.name FROM roles r
		JOIN tenants t ON t.id = r.tenant_id
		WHERE t.tenant_name='public'`)
	if err != nil {
		t.Fatalf("list public roles: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan role name: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("role name rows: %v", err)
	}

	substringDenylist := []string{
		"Notifications",
		"Approval",
		"Inventory",
		"User Access",
		"Local Test",
		"OCM",
	}
	for _, sub := range substringDenylist {
		var found []string
		for _, name := range names {
			if strings.Contains(name, sub) {
				found = append(found, name)
			}
		}
		if len(found) != 0 {
			t.Errorf("unexpected roles containing %q: %v", sub, found)
		}
	}
}
