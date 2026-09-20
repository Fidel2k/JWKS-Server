package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"
)

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

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := []JWK{}

	// Only include the key if it has not expired.
	if validKey != nil && validKey.ExpiresAt.After(time.Now()) {
		publicKey := &validKey.PrivateKey.PublicKey

		// Convert RSA modulus to Base64 URL encoding.
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

		// Convert RSA exponent to Base64 URL encoding.
		eBytes := big.NewInt(int64(publicKey.E)).Bytes()
		e := base64.RawURLEncoding.EncodeToString(eBytes)

		keys = append(keys, JWK{
			Kty: "RSA",
			Kid: validKey.Kid,
			Use: "sig",
			Alg: "RS256",
			N:   n,
			E:   e,
		})
	}

	response := JWKS{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to create JWKS response", http.StatusInternalServerError)
	}
}