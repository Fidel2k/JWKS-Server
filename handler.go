package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"time"
)

// public key info sent to client
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// holds list of keys
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// hanles requests to jwk endpoint
func (s *keyStore) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		//only allow GET request
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := []JWK{}

	stored, err := s.read(false, time.Now().Unix())
	if err != nil {
		http.Error(w, "Failed to read keys", http.StatusInternalServerError)
		return
	}
	for _, key := range stored {
		publicKey := &key.PrivateKey.PublicKey
		keys = append(keys, JWK{Kty: "RSA", Kid: key.Kid, Use: "sig", Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())})
	}

	response := JWKS{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to create JWKS response", http.StatusInternalServerError)
	}
}
func (s *keyStore) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Presence of expired selects expired keys, even for ?expired=false.
	_, expired := r.URL.Query()["expired"]
	now := time.Now()
	stored, err := s.read(expired, now.Unix())
	if err != nil || len(stored) == 0 {
		http.Error(w, "No signing key available", http.StatusInternalServerError)
		return
	}
	key := stored[len(stored)-1]
	expiration := key.ExpiresAt

	claims := jwt.MapClaims{
		"sub": "userABC",
		"iat": now.Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//Add the key ID to the JWT header
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(signedToken))
}
