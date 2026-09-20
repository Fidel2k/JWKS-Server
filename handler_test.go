package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Creates fresh keys before each handler test.
func setupTestKeys(t *testing.T) {
	t.Helper()

	var err error

	validKey, err = generateKeyPair(
		"valid-key",
		time.Now().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}

	expiredKey, err = generateKeyPair(
		"expired-key",
		time.Now().Add(-1*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	key, err := generateKeyPair(
		"test-key",
		time.Now().Add(1*time.Hour),
	)

	if err != nil {
		t.Fatal(err)
	}

	if key.PrivateKey == nil {
		t.Error("Private key was not generated")
	}

	if key.Kid != "test-key" {
		t.Errorf("Expected kid test-key, got %s", key.Kid)
	}
}

func TestInitializeKeys(t *testing.T) {
	err := initializeKeys()

	if err != nil {
		t.Fatal(err)
	}

	if validKey == nil {
		t.Error("Valid key was not created")
	}

	if expiredKey == nil {
		t.Error("Expired key was not created")
	}

	if validKey.ExpiresAt.Before(time.Now()) {
		t.Error("Valid key should not be expired")
	}

	if expiredKey.ExpiresAt.After(time.Now()) {
		t.Error("Expired key should be expired")
	}
}

func TestHomeHandler(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", response.Code)
	}

	if !strings.Contains(response.Body.String(), "JWKS Server is running!") {
		t.Error("Home page did not return expected message")
	}
}

func TestJWKSHandler(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", response.Code)
	}

	var jwks JWKS

	err := json.NewDecoder(response.Body).Decode(&jwks)
	if err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 valid key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "valid-key" {
		t.Errorf(
			"Expected valid-key, got %s",
			jwks.Keys[0].Kid,
		)
	}

	if jwks.Keys[0].Kty != "RSA" {
		t.Errorf(
			"Expected RSA key type, got %s",
			jwks.Keys[0].Kty,
		)
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodPost,
		"/.well-known/jwks.json",
		nil,
	)

	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			response.Code,
		)
	}
}

func TestAuthValidToken(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"Expected status 200, got %d",
			response.Code,
		)
	}

	tokenString := strings.TrimSpace(response.Body.String())

	parser := jwt.NewParser()

	token, _, err := parser.ParseUnverified(
		tokenString,
		jwt.MapClaims{},
	)

	if err != nil {
		t.Fatal(err)
	}

	if token.Header["kid"] != "valid-key" {
		t.Errorf(
			"Expected valid-key, got %v",
			token.Header["kid"],
		)
	}

	claims := token.Claims.(jwt.MapClaims)

	expiration, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}

	if expiration.Time.Before(time.Now()) {
		t.Error("Valid JWT should not be expired")
	}
}

func TestAuthExpiredToken(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"Expected status 200, got %d",
			response.Code,
		)
	}

	tokenString := strings.TrimSpace(response.Body.String())

	parser := jwt.NewParser()

	token, _, err := parser.ParseUnverified(
		tokenString,
		jwt.MapClaims{},
	)

	if err != nil {
		t.Fatal(err)
	}

	if token.Header["kid"] != "expired-key" {
		t.Errorf(
			"Expected expired-key, got %v",
			token.Header["kid"],
		)
	}

	claims := token.Claims.(jwt.MapClaims)

	expiration, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}

	if expiration.Time.After(time.Now()) {
		t.Error("Expired JWT should have an expired expiration time")
	}
}

func TestAuthRejectsGet(t *testing.T) {
	setupTestKeys(t)

	router := newRouter()

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth",
		nil,
	)

	response := httptest.NewRecorder()

	router.ServeHTTP(response, req)

	if response.Code != http.StatusMethodNotAllowed {
		t.Errorf(
			"Expected status 405, got %d",
			response.Code,
		)
	}
}