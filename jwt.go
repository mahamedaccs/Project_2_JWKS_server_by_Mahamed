package main

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func issueJWTWithKey(kid string, priv *rsa.PrivateKey, now time.Time, expUnix int64) (string, error) {
	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": expUnix,
		"iss": "jwks-server",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid

	return tok.SignedString(priv)
}