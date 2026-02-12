package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func issueJWT(k KeyPair, now time.Time, expired bool) (string, error) {
	var exp time.Time
	if expired {
		exp = now.Add(-5 * time.Minute)
	} else {
		exp = now.Add(15 * time.Minute)
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"iss": "jwks-server",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = k.KID

	return tok.SignedString(k.Priv)
}
