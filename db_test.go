package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDBSeedAndQueries(t *testing.T) {
	fixed := time.Unix(1700000000, 0)

	// Use temp directory so we don't interfere with your real DB
	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	db, err := openDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}

	// First seed should insert keys
	if err := ensureSeedKeys(db, fixed); err != nil {
		t.Fatal(err)
	}

	// Second seed should do nothing (covers count>0 branch)
	if err := ensureSeedKeys(db, fixed); err != nil {
		t.Fatal(err)
	}

	// DB file exists
	if _, err := os.Stat(filepath.Join(tmp, DBFileName)); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}

	// Query valid key
	v, err := getOneValidKey(db, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if v.KID == 0 || len(v.PEM) == 0 {
		t.Fatal("valid key row missing fields")
	}
	priv, err := parseRSAPrivateKeyFromPEM(v.PEM)
	if err != nil || priv == nil {
		t.Fatalf("failed to parse valid pem: %v", err)
	}

	// Query expired key
	e, err := getOneExpiredKey(db, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if e.KID == 0 || len(e.PEM) == 0 {
		t.Fatal("expired key row missing fields")
	}
	priv2, err := parseRSAPrivateKeyFromPEM(e.PEM)
	if err != nil || priv2 == nil {
		t.Fatalf("failed to parse expired pem: %v", err)
	}

	// All valid keys
	all, err := getAllValidKeys(db, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 1 {
		t.Fatal("expected at least one valid key")
	}
}

func TestParseRSAPrivateKeyFromPEMBadInput(t *testing.T) {
	_, err := parseRSAPrivateKeyFromPEM([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}