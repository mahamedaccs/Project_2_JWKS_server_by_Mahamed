package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildHandlerCreatesDBAndServesJWKS(t *testing.T) {
	fixed := time.Unix(1700000000, 0)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	h, cleanup, err := buildHandler(fixed)
	if err != nil {
		t.Fatalf("buildHandler error: %v", err)
	}
	defer cleanup()

	if _, err := os.Stat(filepath.Join(tmp, DBFileName)); err != nil {
		t.Fatalf("expected db file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestBuildHandlerFailsOnBadDBFileName(t *testing.T) {
	fixed := time.Unix(1700000000, 0)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	// Create a directory with the same name as the DB file; SQLite can't open a directory as a file.
	_ = os.Mkdir(DBFileName, 0755)

	_, _, err := buildHandler(fixed)
	if err == nil {
		t.Fatal("expected error when DBFileName is a directory")
	}
}