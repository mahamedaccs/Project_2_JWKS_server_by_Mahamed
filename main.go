package main

import (
	"log"
	"net/http"
)

func main() {
	s := NewServer()
	addr := ":8080"
	log.Printf("JWKS server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
