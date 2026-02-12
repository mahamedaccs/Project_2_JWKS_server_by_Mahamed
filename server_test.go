package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSOnlyReturnsUnexpiredKeys(t *testing.T) {
	fixed := time.Unix(1700000000, 0)

	s := &Server{
		Keys: NewKeyStoreAt(fixed),
		Now:  func() time.Time { return fixed },
	}

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
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid == "" || jwks.Keys[0].N == "" || jwks.Keys[0].E == "" {
		t.Fatalf("jwk missing fields: %+v", jwks.Keys[0])
	}
}

func TestAuthIssuesJWTWithKid(t *testing.T) {
	fixed := time.Unix(1700000000, 0)

	s := &Server{
		Keys: NewKeyStoreAt(fixed),
		Now:  func() time.Time { return fixed },
	}

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
	fixed := time.Unix(1700000000, 0)

	s := &Server{
		Keys: NewKeyStoreAt(fixed),
		Now:  func() time.Time { return fixed },
	}

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
	if int64(expF) >= fixed.Unix() {
		t.Fatalf("expected exp < now, got exp=%d now=%d", int64(expF), fixed.Unix())
	}
}

func TestMethods(t *testing.T) {
	// For method tests, time doesn't matter.
	s := NewServer()
	rr := httptest.NewRecorder()

	req1 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	s.routes().ServeHTTP(rr, req1)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	s.routes().ServeHTTP(rr, req2)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestContentTypes(t *testing.T) {
	// For content-type tests, time doesn't matter.
	s := NewServer()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	s.routes().ServeHTTP(rr, req)

	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected json content-type, got %q", rr.Header().Get("Content-Type"))
	}
}
