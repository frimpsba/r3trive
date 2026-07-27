package postgres

import (
	"testing"
)

func TestPostgresStoreNew(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Errorf("expected error for empty DSN")
	}

	store, err := New("postgres://user:pass@localhost:5432/r3trive?sslmode=disable")
	if err != nil {
		t.Fatalf("unexpected initialization error: %v", err)
	}
	if store.DSN() != "postgres://user:pass@localhost:5432/r3trive?sslmode=disable" {
		t.Errorf("DSN mismatch")
	}
	_ = store.Close()
}
