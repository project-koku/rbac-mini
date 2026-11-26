package store_test

import (
	"strings"
	"testing"

	"rbac-go/internal/store"
	"rbac-go/internal/testdb"
)

// TestMigrateSchemaVersionGuard runs the stamp + refuse-newer contract on the
// suite's backend (SQLite by default, Postgres when RBAC_TEST_POSTGRES is
// set), so both dialects of the portable stamping SQL are exercised.
func TestMigrateSchemaVersionGuard(t *testing.T) {
	db := testdb.Open(t) // already migrated once

	read := func() []int {
		t.Helper()
		rows, err := db.Query(`SELECT version FROM schema_version ORDER BY id`)
		if err != nil {
			t.Fatalf("select schema_version: %v", err)
		}
		defer func() { _ = rows.Close() }()
		var out []int
		for rows.Next() {
			var v int
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}

	if got := read(); len(got) != 1 || got[0] != store.SchemaVersion {
		t.Fatalf("stamp = %v, want [%d]", got, store.SchemaVersion)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if got := read(); len(got) != 1 || got[0] != store.SchemaVersion {
		t.Fatalf("stamp after second Migrate = %v, want [%d]", got, store.SchemaVersion)
	}

	if _, err := db.Exec(`UPDATE schema_version SET version = ?`, store.SchemaVersion+1); err != nil {
		t.Fatalf("stamp newer: %v", err)
	}
	err := store.Migrate(db)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Migrate against newer schema: err = %v, want 'newer' error", err)
	}
	if got := read(); len(got) != 1 || got[0] != store.SchemaVersion+1 {
		t.Errorf("stamp after refusal = %v, want [%d]", got, store.SchemaVersion+1)
	}
}
