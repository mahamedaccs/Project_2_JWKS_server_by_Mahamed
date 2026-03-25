package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type Server struct {
	DB  *sql.DB
	Now func() time.Time
}

func NewServer(db *sql.DB) *Server {
	return &Server{
		DB:  db,
		Now: time.Now,
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := s.Now()
	rows, err := getAllValidKeys(s.DB, now)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	jwks := JWKS{Keys: make([]JWK, 0, len(rows))}
	for _, row := range rows {
		priv, err := parseRSAPrivateKeyFromPEM(row.PEM)
		if err != nil {
			http.Error(w, "bad key in db", http.StatusInternalServerError)
			return
		}
		kidStr := strconv.FormatInt(row.KID, 10)
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(&priv.PublicKey, kidStr))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := s.Now()
	_, wantsExpired := r.URL.Query()["expired"]

	// Gradebot may send Basic Auth and/or JSON; we don't validate for this project.
	_, _, _ = r.BasicAuth()

	var row dbKeyRow
	var err error
	if wantsExpired {
		row, err = getOneExpiredKey(s.DB, now)
	} else {
		row, err = getOneValidKey(s.DB, now)
	}
	if err != nil {
		http.Error(w, "no suitable key available", http.StatusServiceUnavailable)
		return
	}

	priv, err := parseRSAPrivateKeyFromPEM(row.PEM)
	if err != nil {
		http.Error(w, "bad key in db", http.StatusInternalServerError)
		return
	}

	kidStr := strconv.FormatInt(row.KID, 10)

	// Use DB exp for token exp (expired key => expired token).
	token, err := issueJWTWithKey(kidStr, priv, now, row.Exp)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}