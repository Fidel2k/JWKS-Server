package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Public key information returned to clients.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Returns all unexpired public keys from the database.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	storedKeys, err := readKeys(db, false)
	if err != nil {
		http.Error(w, "Failed to read keys", http.StatusInternalServerError)
		return
	}

	response := JWKS{Keys: []JWK{}}

	for _, key := range storedKeys {
		publicKey := &key.PrivateKey.PublicKey

		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(
			big.NewInt(int64(publicKey.E)).Bytes(),
		)

		response.Keys = append(response.Keys, JWK{
			Kty: "RSA",
			Kid: key.Kid,
			Use: "sig",
			Alg: "RS256",
			N:   n,
			E:   e,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

// Mocks authentication and signs a JWT using a stored private key.
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Any presence of "expired" selects expired keys.
	_, expired := r.URL.Query()["expired"]

	keys, err := readKeys(db, expired)
	if err != nil {
		http.Error(w, "Failed to read keys", http.StatusInternalServerError)
		return
	}

	if len(keys) == 0 {
		http.Error(w, "No signing key available", http.StatusInternalServerError)
		return
	}

	key := keys[len(keys)-1]

	// Credentials are intentionally not validated for this assignment.
	claims := jwt.MapClaims{
		"sub": "userABC",
		"iat": time.Now().Unix(),
		"exp": key.ExpiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(signedToken))
}
