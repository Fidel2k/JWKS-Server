package main

import (
	"crypto/rand"
	"crypto/rsa"
	"time"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

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