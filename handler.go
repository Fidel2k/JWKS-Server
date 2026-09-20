package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
)
//public key info sent to client
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
//holds list of keys
type JWKS struct {
	Keys []JWK `json:"keys"`
}
//hanles requests to jwk endpoint
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		//only allow GET request
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := []JWK{}

	// Only include the key if it has not expired
	if validKey != nil && validKey.ExpiresAt.After(time.Now()) {
		publicKey := &validKey.PrivateKey.PublicKey

		// Convert RSA modulus to Base64 URL encoding
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

		// Convert RSA exponent to Base64 URL encoding
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
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := validKey

	//If the expired query parameter exists and use the expired key
	if _, exists := r.URL.Query()["expired"]; exists {
		key = expiredKey
	}

	now := time.Now()

	var expiration time.Time

	if key == expiredKey {
		expiration = now.Add(-1 * time.Hour)
	} else {
		expiration = now.Add(1 * time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
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