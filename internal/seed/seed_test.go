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

// TestBootstrapGrantsCostAdministrator mirrors
// operator render_bootstrap_script: tenant + "CI Test Admin" group carrying
// the seeded Cost Administrator role + one principal per service account.
// End-to-end check: the bootstrapped principal sees cost-management:*:*.
func TestBootstrapGrantsCostAdministrator(t *testing.T) {
	db := testDB(t)
	if err := Seed(db); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	users := []string{"cost-mgmt-operator", "admin"}
	if err := Bootstrap(db, "100001", "acct1111111", users); err != nil {
		t.Fatalf("first Bootstrap returned error: %v", err)
	}

	var tenantName string
	var ready int
	if err := db.QueryRow(`SELECT tenant_name, ready FROM tenants WHERE org_id='100001'`).Scan(&tenantName, &ready); err != nil {
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
	if role != "Cost Administrator" {
		t.Errorf("role = %q, want %q", role, "Cost Administrator")
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
	}

	got, err := access.Query(db, "100001", "cost-mgmt-operator", []string{"cost-management"}, false)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Permission != "cost-management:*:*" {
		t.Errorf("access = %v, want [cost-management:*:*]", got)
	}

	// Idempotent like the seed: re-running changes nothing.
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

// TestBootstrapRequiresSeededCostAdministrator: bootstrap looks up the
// public Cost Administrator role; without Seed it must fail (not create a
// half-wired org).
func TestBootstrapRequiresSeededCostAdministrator(t *testing.T) {
	db := testDB(t)
	if err := Bootstrap(db, "100001", "acct", []string{"alice"}); err == nil {
		t.Fatal("Bootstrap without Seed succeeded, want error")
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

// TestSeedCostPriceListRoles: operator-parity packaged roles for Cost Price
// List Administrator/Viewer. They must be system, not admin_default, and
// must not attach to Default admin access (unlike Cost Administrator /
// Sources administrator).
func TestSeedCostPriceListRoles(t *testing.T) {
	db := testDB(t)

	if err := Seed(db); err != nil {
		t.Fatalf("first Seed returned error: %v", err)
	}

	type wantRole struct {
		name        string
		displayName string
		perms       []string
	}
	want := []wantRole{
		{
			name:        "Cost Price List Administrator",
			displayName: "Cost Price List administrator",
			perms:       []string{"cost-management:cost_model:*", "cost-management:settings:*"},
		},
		{
			name:        "Cost Price List Viewer",
			displayName: "Cost Price List viewer",
			perms:       []string{"cost-management:cost_model:read", "cost-management:settings:read"},
		},
	}

	roleAccessCounts := map[string]int{}
	for _, r := range want {
		var system, adminDefault, platformDefault int
		var displayName string
		err := db.QueryRow(`SELECT r.system, r.admin_default, r.platform_default, r.display_name
			FROM roles r
			JOIN tenants t ON t.id = r.tenant_id
			WHERE r.name=? AND t.tenant_name='public'`, r.name).Scan(
			&system, &adminDefault, &platformDefault, &displayName)
		if err != nil {
			t.Fatalf("role %q missing: %v", r.name, err)
		}
		if system != 1 {
			t.Errorf("role %q system = %d, want 1", r.name, system)
		}
		if adminDefault != 0 {
			t.Errorf("role %q admin_default = %d, want 0", r.name, adminDefault)
		}
		if platformDefault != 0 {
			t.Errorf("role %q platform_default = %d, want 0", r.name, platformDefault)
		}
		if displayName != r.displayName {
			t.Errorf("role %q display_name = %q, want %q", r.name, displayName, r.displayName)
		}

		rows, err := db.Query(`SELECT p.permission FROM permissions p
			JOIN access a ON a.permission_id = p.id
			JOIN roles r ON r.id = a.role_id
			JOIN tenants t ON t.id = r.tenant_id
			WHERE r.name=? AND t.tenant_name='public'
			ORDER BY p.permission`, r.name)
		if err != nil {
			t.Fatalf("access query for %q: %v", r.name, err)
		}
		var got []string
		for rows.Next() {
			var perm string
			if err := rows.Scan(&perm); err != nil {
				t.Fatalf("scan access for %q: %v", r.name, err)
			}
			got = append(got, perm)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows for %q: %v", r.name, err)
		}
		_ = rows.Close()
		wantPerms := append([]string(nil), r.perms...)
		slices.Sort(wantPerms)
		if !slices.Equal(got, wantPerms) {
			t.Errorf("role %q grants = %v, want %v", r.name, got, wantPerms)
		}
		roleAccessCounts[r.name] = len(got)

		var onAdminGroup int
		if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
			JOIN policies p ON p.id = pr.policy_id
			JOIN roles r ON r.id = pr.role_id
			WHERE p.name='Default admin access' AND r.name=?`, r.name).Scan(&onAdminGroup); err != nil {
			t.Fatalf("Default admin access link check for %q: %v", r.name, err)
		}
		if onAdminGroup != 0 {
			t.Errorf("role %q linked to Default admin access, want not linked", r.name)
		}
	}

	var linked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		WHERE p.name='Default admin access'`).Scan(&linked); err != nil || linked != 2 {
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
		WHERE p.name='Default admin access'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("after re-seed, Default admin access roles = %d, err = %v, want 2", linked, err)
	}
}

// TestSeedCostOpenShiftViewer: operator-parity packaged role for Cost
// OpenShift Viewer. System, not admin_default, not on Default admin access;
// grant is exactly cost-management:openshift.cluster:*.
func TestSeedCostOpenShiftViewer(t *testing.T) {
	db := testDB(t)

	if err := Seed(db); err != nil {
		t.Fatalf("first Seed returned error: %v", err)
	}

	const (
		roleName    = "Cost OpenShift Viewer"
		displayName = "Cost OpenShift viewer"
		permission  = "cost-management:openshift.cluster:*"
	)

	var system, adminDefault, platformDefault int
	var gotDisplay string
	err := db.QueryRow(`SELECT r.system, r.admin_default, r.platform_default, r.display_name
		FROM roles r
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'`, roleName).Scan(
		&system, &adminDefault, &platformDefault, &gotDisplay)
	if err != nil {
		t.Fatalf("role %q missing: %v", roleName, err)
	}
	if system != 1 {
		t.Errorf("role %q system = %d, want 1", roleName, system)
	}
	if adminDefault != 0 {
		t.Errorf("role %q admin_default = %d, want 0", roleName, adminDefault)
	}
	if platformDefault != 0 {
		t.Errorf("role %q platform_default = %d, want 0", roleName, platformDefault)
	}
	if gotDisplay != displayName {
		t.Errorf("role %q display_name = %q, want %q", roleName, gotDisplay, displayName)
	}

	rows, err := db.Query(`SELECT p.permission FROM permissions p
		JOIN access a ON a.permission_id = p.id
		JOIN roles r ON r.id = a.role_id
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'
		ORDER BY p.permission`, roleName)
	if err != nil {
		t.Fatalf("access query for %q: %v", roleName, err)
	}
	var got []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			t.Fatalf("scan access for %q: %v", roleName, err)
		}
		got = append(got, perm)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows for %q: %v", roleName, err)
	}
	_ = rows.Close()
	wantPerms := []string{permission}
	if !slices.Equal(got, wantPerms) {
		t.Errorf("role %q grants = %v, want %v", roleName, got, wantPerms)
	}
	accessCount := len(got)

	var onAdminGroup int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		JOIN roles r ON r.id = pr.role_id
		WHERE p.name='Default admin access' AND r.name=?`, roleName).Scan(&onAdminGroup); err != nil {
		t.Fatalf("Default admin access link check for %q: %v", roleName, err)
	}
	if onAdminGroup != 0 {
		t.Errorf("role %q linked to Default admin access, want not linked", roleName)
	}

	var linked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		WHERE p.name='Default admin access'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("Default admin access roles = %d, err = %v, want 2", linked, err)
	}

	if err := Seed(db); err != nil {
		t.Fatalf("second Seed returned error: %v", err)
	}
	var roleN int
	if err := db.QueryRow(`SELECT COUNT(*) FROM roles r
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'`, roleName).Scan(&roleN); err != nil || roleN != 1 {
		t.Errorf("after re-seed, role %q count = %d, err = %v, want 1", roleName, roleN, err)
	}
	var accessN int
	if err := db.QueryRow(`SELECT COUNT(*) FROM access a
		JOIN roles r ON r.id = a.role_id
		JOIN tenants t ON t.id = r.tenant_id
		WHERE r.name=? AND t.tenant_name='public'`, roleName).Scan(&accessN); err != nil {
		t.Fatalf("after re-seed, access count for %q: %v", roleName, err)
	}
	if accessN != accessCount {
		t.Errorf("after re-seed, role %q access count = %d, want %d", roleName, accessN, accessCount)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_roles pr
		JOIN policies p ON p.id = pr.policy_id
		WHERE p.name='Default admin access'`).Scan(&linked); err != nil || linked != 2 {
		t.Errorf("after re-seed, Default admin access roles = %d, err = %v, want 2", linked, err)
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
