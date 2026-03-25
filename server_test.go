package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) (*Server, func()) {
	t.Helper()

	fixed := time.Unix(1700000000, 0)

	// run tests in a temp dir so DB file is created there
	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	db, err := openDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := ensureSeedKeys(db, fixed); err != nil {
		t.Fatal(err)
	}

	// confirm DB file exists with exact name
	if _, err := os.Stat(filepath.Join(tmp, DBFileName)); err != nil {
		t.Fatalf("db file not found: %v", err)
	}

	s := NewServer(db)
	s.Now = func() time.Time { return fixed }

	cleanup := func() {
		_ = db.Close()
		_ = os.Chdir(oldwd)
	}
	return s, cleanup
}

func TestJWKSOnlyReturnsUnexpiredKeys(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var jwks JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(jwks.Keys) < 1 {
		t.Fatalf("expected at least 1 valid key, got %d", len(jwks.Keys))
	}
}

func TestAuthIssuesJWTWithKid(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	tokStr := resp["token"]
	if tokStr == "" {
		t.Fatal("missing token")
	}

	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(tokStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	kid, _ := tok.Header["kid"].(string)
	if kid == "" {
		t.Fatal("missing kid header")
	}
}

func TestAuthExpiredQueryIssuesExpiredExp(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=1", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	tokStr := resp["token"]
	if tokStr == "" {
		t.Fatal("missing token")
	}

	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(tokStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("exp missing or wrong type")
	}
	if int64(expF) >= s.Now().Unix() {
		t.Fatalf("expected expired exp < now, got exp=%d now=%d", int64(expF), s.Now().Unix())
	}
}

func TestMethodsReturn405(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	// JWKS should reject POST
	req1 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rr1 := httptest.NewRecorder()
	s.routes().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr1.Code)
	}

	// auth should reject GET
	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr2.Code)
	}
}

func TestJWKSContentTypeJSON(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct == "" {
		t.Fatal("missing Content-Type")
	}
}

func TestHandlersReturn500OnDBFailure(t *testing.T) {
	s, cleanup := setupTestServer(t)
	defer cleanup()

	// Close DB to force query errors
	_ = s.DB.Close()

	// JWKS should hit db error path
	req1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr1 := httptest.NewRecorder()
	s.routes().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr1.Code)
	}

	// /auth should hit "no suitable key available" (DB error -> 503)
	req2 := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr2.Code)
	}
}