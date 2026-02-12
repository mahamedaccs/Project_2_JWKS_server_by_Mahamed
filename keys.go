package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"sync"
	"time"
)

type KeyPair struct {
	KID       string
	Priv      *rsa.PrivateKey
	ExpiresAt time.Time
}

type KeyStore struct {
	mu   sync.RWMutex
	keys []KeyPair
}

func NewKeyStore() *KeyStore {
	return NewKeyStoreAt(time.Now())
}

func NewKeyStoreAt(now time.Time) *KeyStore {
	ks := &KeyStore{}

	// One active key + one expired key based on the provided "now"
	active := mustGenerateKey(now.Add(24 * time.Hour))
	expired := mustGenerateKey(now.Add(-24 * time.Hour))

	ks.keys = []KeyPair{active, expired}
	return ks
}

func mustGenerateKey(exp time.Time) KeyPair {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	kidBytes := make([]byte, 16)
	if _, err := rand.Read(kidBytes); err != nil {
		panic(err)
	}

	return KeyPair{
		KID:       hex.EncodeToString(kidBytes),
		Priv:      priv,
		ExpiresAt: exp,
	}
}

func (ks *KeyStore) ActiveKeys(now time.Time) []KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	out := make([]KeyPair, 0, len(ks.keys))
	for _, k := range ks.keys {
		if now.Before(k.ExpiresAt) {
			out = append(out, k)
		}
	}
	return out
}

func (ks *KeyStore) PickActive(now time.Time) (KeyPair, bool) {
	aks := ks.ActiveKeys(now)
	if len(aks) == 0 {
		return KeyPair{}, false
	}
	return aks[0], true
}

func (ks *KeyStore) PickExpired(now time.Time) (KeyPair, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	for _, k := range ks.keys {
		if !now.Before(k.ExpiresAt) {
			return k, true
		}
	}
	return KeyPair{}, false
}
