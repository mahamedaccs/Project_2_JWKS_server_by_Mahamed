package main

import (
	"encoding/json"
	"net/http"
	"time"
)

type Server struct {
	Keys *KeyStore
	Now  func() time.Time
}

func NewServer() *Server {
	return &Server{
		Keys: NewKeyStore(),
		Now:  time.Now,
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
	active := s.Keys.ActiveKeys(now)

	jwks := JWKS{Keys: make([]JWK, 0, len(active))}
	for _, k := range active {
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(&k.Priv.PublicKey, k.KID))
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

	var kp KeyPair
	var ok bool
	if wantsExpired {
		kp, ok = s.Keys.PickExpired(now)
	} else {
		kp, ok = s.Keys.PickActive(now)
	}
	if !ok {
		http.Error(w, "no suitable key available", http.StatusServiceUnavailable)
		return
	}

	token, err := issueJWT(kp, now, wantsExpired)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
