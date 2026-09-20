package main

import (
	"crypto/rand"
	"crypto/rsa"
	"time"
)
//stores the RSA private key,id, and expiration
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}
//generates a new RSA key 
func generateKeyPair(kid string, expiresAt time.Time) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		Kid:        kid,
		ExpiresAt:  expiresAt,
	}, nil
}