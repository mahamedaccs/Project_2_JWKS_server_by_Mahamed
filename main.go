package main

import (
	"log"
	"net/http"
	"time"
)

// buildHandler initializes the DB (schema + seed) and returns the HTTP handler.
// This lets tests cover startup logic without binding to a network port.
func buildHandler(now time.Time) (http.Handler, func(), error) {
	db, err := openDB()
	if err != nil {
		return nil, nil, err
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	if err := ensureSeedKeys(db, now); err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	s := NewServer(db)

	cleanup := func() {
		_ = db.Close()
	}

	return s.routes(), cleanup, nil
}

func main() {
	h, cleanup, err := buildHandler(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	log.Printf("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", h))
}