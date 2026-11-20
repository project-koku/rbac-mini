package permission

import (
	"slices"
	"testing"

	"rbac-go/internal/store"
	"rbac-go/internal/testdb"
)

func seedPerms(t *testing.T, db *store.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants(org_id, tenant_name, ready) VALUES('public','public',1)`)
	exec(`INSERT INTO tenants(org_id, tenant_name, account_id, ready) VALUES('100001','acct1111111','1111111',1)`)
	rows := []struct{ app, res, verb, perm string }{
		{"cost-management", "aws.account", "read", "cost-management:aws.account:read"},
		{"cost-management", "*", "*", "cost-management:*:*"},
		{"sources", "*", "*", "sources:*:*"},
		{"*", "*", "*", "*:*:*"},
		{"app", "resource", "verb", "app:resource:verb"},
	}
	for _, r := range rows {
		exec(`INSERT INTO permissions(application, resource_type, verb, permission, tenant_id)
			VALUES(?,?,?,?,(SELECT id FROM tenants WHERE org_id='100001'))`,
			r.app, r.res, r.verb, r.perm)
	}
}

func names(items []Permission) []string {
	out := make([]string, 0, len(items))
	for _, p := range items {
		out = append(out, p.Permission)
	}
	return out
}

// TestListHappyPath: unfiltered List returns tenant permissions ordered by string.
func TestListHappyPath(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 || len(items) != 5 {
		t.Fatalf("total = %d len = %d, want 5; got %v", total, len(items), names(items))
	}
	wantOrder := []string{
		"*:*:*",
		"app:resource:verb",
		"cost-management:*:*",
		"cost-management:aws.account:read",
		"sources:*:*",
	}
	if !slices.Equal(names(items), wantOrder) {
		t.Errorf("order = %v, want %v", names(items), wantOrder)
	}
}

// TestListExcludeGlobals drops any permission with a '*' segment.
func TestListExcludeGlobals(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{ExcludeGlobals: true}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := names(items)
	if total != 2 || len(got) != 2 {
		t.Fatalf("total = %d got = %v, want 2 non-global rows", total, got)
	}
	want := []string{"app:resource:verb", "cost-management:aws.account:read"}
	if !slices.Equal(got, want) {
		t.Errorf("got = %v, want %v", got, want)
	}
}

// TestListAllowedOnlyEmptyAllowList mirrors Django: "".split(",") == [""]
// matches nothing when AllowedOnly is set with an empty allow list.
func TestListAllowedOnlyEmptyAllowList(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{AllowedOnly: true, AllowList: nil}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("empty allow-list: total = %d items = %v, want none", total, names(items))
	}

	items, total, err = List(db, "100001", Filter{AllowedOnly: true, AllowList: []string{}}, 20, 0)
	if err != nil {
		t.Fatalf("List empty slice: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("empty slice allow-list: total = %d items = %v, want none", total, names(items))
	}
}

// TestListAllowedOnlyFiltersToAllowList restricts applications.
func TestListAllowedOnlyFiltersToAllowList(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{
		AllowedOnly: true, AllowList: []string{"cost-management"},
	}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := names(items)
	if total != 2 || len(got) != 2 {
		t.Fatalf("got = %v (total %d), want two cost-management rows", got, total)
	}
	for _, p := range got {
		if p != "cost-management:*:*" && p != "cost-management:aws.account:read" {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

// TestListAllowedOnlyAndExcludeGlobals matches the wizard Step 2 query.
func TestListAllowedOnlyAndExcludeGlobals(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{
		AllowedOnly: true, AllowList: []string{"cost-management"}, ExcludeGlobals: true,
	}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Permission != "cost-management:aws.account:read" {
		t.Fatalf("got = %v (total %d), want [cost-management:aws.account:read]", names(items), total)
	}
}

// TestOptionsHappyPath returns distinct application values.
func TestOptionsHappyPath(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	apps, err := Options(db, "100001", "application", Filter{})
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	want := []string{"*", "app", "cost-management", "sources"}
	if !slices.Equal(apps, want) {
		t.Errorf("applications = %v, want %v", apps, want)
	}
}

// TestOptionsExcludeGlobalsAndAllowedOnly applies the same filter clauses.
func TestOptionsExcludeGlobalsAndAllowedOnly(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	apps, err := Options(db, "100001", "application", Filter{
		ExcludeGlobals: true, AllowedOnly: true, AllowList: []string{"cost-management", "app"},
	})
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	want := []string{"app", "cost-management"}
	if !slices.Equal(apps, want) {
		t.Errorf("applications = %v, want %v", apps, want)
	}

	empty, err := Options(db, "100001", "application", Filter{AllowedOnly: true})
	if err != nil {
		t.Fatalf("Options empty allow: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty allow Options = %v, want []", empty)
	}
}

// TestOptionsInvalidField rejects fields outside application|resource_type|verb.
func TestOptionsInvalidField(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)
	if _, err := Options(db, "100001", "bogus", Filter{}); err == nil {
		t.Fatal("Options(bogus) succeeded, want error")
	}
}

// TestListAndOptionsByResourceAndVerb hits the resource_type/verb IN clauses
// and Options for those fields.
func TestListAndOptionsByResourceAndVerb(t *testing.T) {
	db := testdb.Open(t)
	seedPerms(t, db)

	items, total, err := List(db, "100001", Filter{
		ResourceTypes: []string{"aws.account"},
		Verbs:         []string{"read"},
	}, 20, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Permission != "cost-management:aws.account:read" {
		t.Fatalf("got = %v (total %d), want [cost-management:aws.account:read]", names(items), total)
	}

	resources, err := Options(db, "100001", "resource_type", Filter{Applications: []string{"cost-management"}})
	if err != nil {
		t.Fatalf("Options resource_type: %v", err)
	}
	if !slices.Contains(resources, "aws.account") || !slices.Contains(resources, "*") {
		t.Errorf("resource_type options = %v, want aws.account and *", resources)
	}
	verbs, err := Options(db, "100001", "verb", Filter{Applications: []string{"app"}})
	if err != nil {
		t.Fatalf("Options verb: %v", err)
	}
	if !slices.Equal(verbs, []string{"verb"}) {
		t.Errorf("verb options = %v, want [verb]", verbs)
	}
}
