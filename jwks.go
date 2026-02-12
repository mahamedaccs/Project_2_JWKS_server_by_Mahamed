package main

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func base64URLUInt(x *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(x.Bytes())
}

func rsaPublicJWK(pub *rsa.PublicKey, kid string) JWK {
	e := big.NewInt(int64(pub.E))
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64URLUInt(pub.N),
		E:   base64URLUInt(e),
	}
}
