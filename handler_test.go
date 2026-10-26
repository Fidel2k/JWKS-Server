package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Each test uses a temporary database.
func setupTestKeys(t *testing.T) {
	t.Helper()

	testDB, err := openDatabase(
		filepath.Join(t.TempDir(), "test.db"),
	)
	if err != nil {
		t.Fatal(err)
	}

	oldDB := db
	oldValidKey := validKey
	oldExpiredKey := expiredKey

	db = testDB

	t.Cleanup(func() {
		testDB.Close()
		db = oldDB
		validKey = oldValidKey
		expiredKey = oldExpiredKey
	})

	if err := initializeKeys(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	expiration := time.Now().Add(time.Hour)

	key, err := generateKeyPair("test-key", expiration)
	if err != nil {
		t.Fatal(err)
	}

	if key.PrivateKey == nil {
		t.Fatal("Private key was not generated")
	}

	if err := key.PrivateKey.Validate(); err != nil {
		t.Fatalf("Invalid RSA key: %v", err)
	}

	if key.Kid != "test-key" {
		t.Errorf("Expected test-key, got %s", key.Kid)
	}

	if !key.ExpiresAt.Equal(expiration) {
		t.Error("Incorrect expiration")
	}
}

func TestInitializeKeys(t *testing.T) {
	setupTestKeys(t)

	if validKey == nil || expiredKey == nil {
		t.Fatal("Both keys should exist")
	}

	if !validKey.ExpiresAt.After(time.Now()) {
		t.Error("Valid key should not be expired")
	}

	if expiredKey.ExpiresAt.After(time.Now()) {
		t.Error("Expired key should already be expired")
	}

	if validKey.Kid == expiredKey.Kid {
		t.Error("Keys should have different IDs")
	}

	// Running initialization again should reuse saved keys.
	validID := validKey.Kid
	expiredID := expiredKey.Kid

	if err := initializeKeys(); err != nil {
		t.Fatal(err)
	}

	if validKey.Kid != validID || expiredKey.Kid != expiredID {
		t.Error("Initialization did not reuse saved keys")
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Errorf("Expected 2 saved keys, got %d", count)
	}
}

func TestHomeHandler(t *testing.T) {
	setupTestKeys(t)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	newRouter().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", response.Code)
	}

	if !strings.Contains(response.Body.String(), "JWKS Server is running!") {
		t.Error("Missing home page message")
	}
}

func TestJWKSHandler(t *testing.T) {
	setupTestKeys(t)

	// Save another valid key to check that all valid keys are returned.
	extra, err := generateKeyPair("", time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if err := saveKey(db, extra); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)

	newRouter().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", response.Code)
	}

	var result JWKS
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if len(result.Keys) != 2 {
		t.Fatalf("Expected 2 valid keys, got %d", len(result.Keys))
	}

	seen := make(map[string]bool)

	for _, key := range result.Keys {
		seen[key.Kid] = true

		if key.Kid == expiredKey.Kid {
			t.Error("JWKS included an expired key")
		}

		if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
			t.Error("Incorrect JWK properties")
		}

		if key.N == "" || key.E == "" {
			t.Error("Missing public key values")
		}
	}

	if !seen[validKey.Kid] || !seen[extra.Kid] {
		t.Error("JWKS is missing a valid key")
	}
}

func TestWrongMethods(t *testing.T) {
	setupTestKeys(t)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/auth"},
		{http.MethodPut, "/auth"},
		{http.MethodPost, "/.well-known/jwks.json"},
		{http.MethodDelete, "/.well-known/jwks.json"},
	}

	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, test.path, nil)

		newRouter().ServeHTTP(response, request)

		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d",
				test.method, test.path, response.Code)
		}
	}
}

func TestAuthTokens(t *testing.T) {
	setupTestKeys(t)

	tests := []struct {
		name    string
		path    string
		expired bool
		basic   bool
	}{
		{"valid JSON", "/auth", false, false},
		{"valid Basic", "/auth", false, true},
		{"expired true", "/auth?expired=true", true, false},
		{"expired empty", "/auth?expired", true, false},
		{"expired false", "/auth?expired=false", true, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := strings.NewReader(
				`{"username":"userABC","password":"password123"}`,
			)

			request := httptest.NewRequest(http.MethodPost, test.path, body)
			request.Header.Set("Content-Type", "application/json")

			if test.basic {
				request = httptest.NewRequest(http.MethodPost, test.path, nil)
				request.SetBasicAuth("userABC", "password123")
			}

			response := httptest.NewRecorder()
			newRouter().ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("Expected 200, got %d: %s",
					response.Code, response.Body.String())
			}

			expectedKey := validKey
			if test.expired {
				expectedKey = expiredKey
			}

			// Verify the signature as well as the token's claims.
			token, err := jwt.Parse(
				strings.TrimSpace(response.Body.String()),
				func(token *jwt.Token) (interface{}, error) {
					return &expectedKey.PrivateKey.PublicKey, nil
				},
				jwt.WithValidMethods([]string{"RS256"}),
			)

			if test.expired {
				if !errors.Is(err, jwt.ErrTokenExpired) {
					t.Fatalf("Expected expired token error, got %v", err)
				}
				if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
					t.Fatal("Expired token has an invalid signature")
				}
			} else if err != nil || !token.Valid {
				t.Fatalf("Expected valid token, got %v", err)
			}

			if token == nil {
				t.Fatal("Token was not parsed")
			}

			if token.Header["kid"] != expectedKey.Kid {
				t.Errorf("Expected kid %s, got %v",
					expectedKey.Kid, token.Header["kid"])
			}

			claims := token.Claims.(jwt.MapClaims)

			if claims["sub"] != "userABC" {
				t.Error("Incorrect user in token")
			}

			expiration, err := claims.GetExpirationTime()
			if err != nil || expiration == nil {
				t.Fatal("Missing or invalid expiration")
			}

			if expiration.Unix() != expectedKey.ExpiresAt.Unix() {
				t.Error("Token expiration does not match its key")
			}
		})
	}
}

func TestDatabasePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persistent.db")

	firstDB, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstDB.Close()

	key, err := generateKeyPair("", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if err := saveKey(firstDB, key); err != nil {
		t.Fatal(err)
	}

	if err := firstDB.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the same file to simulate a server restart.
	secondDB, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()

	keys, err := readKeys(secondDB, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 saved key, got %d", len(keys))
	}

	if keys[0].Kid != key.Kid {
		t.Error("Key ID changed after reopening database")
	}

	if !keys[0].PrivateKey.Equal(key.PrivateKey) {
		t.Error("Private key changed after reopening database")
	}

	if keys[0].ExpiresAt.Unix() != key.ExpiresAt.Unix() {
		t.Error("Expiration changed after reopening database")
	}
}

func TestEmptyDatabase(t *testing.T) {
	setupTestKeys(t)

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/auth", "/auth?expired=true"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, nil)

		newRouter().ServeHTTP(response, request)

		if response.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500 for missing key, got %d", response.Code)
		}
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	newRouter().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", response.Code)
	}

	if !strings.Contains(response.Body.String(), `"keys":[]`) {
		t.Error("Expected an empty keys array")
	}
}

func TestClosedDatabase(t *testing.T) {
	setupTestKeys(t)
	db.Close()

	if _, err := readKeys(db, false); err == nil {
		t.Error("Reading a closed database should fail")
	}

	if err := saveKey(db, validKey); err == nil {
		t.Error("Saving to a closed database should fail")
	}

	if err := initializeKeys(); err == nil {
		t.Error("Initializing a closed database should fail")
	}

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/auth"},
		{http.MethodGet, "/.well-known/jwks.json"},
	}

	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, test.path, nil)

		newRouter().ServeHTTP(response, request)

		if response.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d", response.Code)
		}
	}
}

func TestInvalidDatabasePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-folder", "test.db")

	testDB, err := openDatabase(path)
	if err == nil {
		testDB.Close()
		t.Fatal("Opening a database in a missing folder should fail")
	}
}

func TestDecodeInvalidKeys(t *testing.T) {
	tests := []string{
		"not PEM data",
		"-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----",
	}

	for _, data := range tests {
		if _, err := decodeKey([]byte(data)); err == nil {
			t.Error("Invalid key data should fail")
		}
	}
}

func TestInvalidStoredKey(t *testing.T) {
	setupTestKeys(t)

	if _, err := db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}

	// SQL-looking text must be stored as data, not executed.
	data := []byte("'; DROP TABLE keys; --")

	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		data,
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 1 {
		t.Error("Expected the inserted row to remain in the table")
	}

	if _, err := readKeys(db, false); err == nil {
		t.Error("Invalid stored PEM should fail")
	}

	if err := initializeKeys(); err == nil {
		t.Error("Initialization should report the invalid stored key")
	}
}

func TestExpirationBoundary(t *testing.T) {
	setupTestKeys(t)

	// A key expiring now belongs in the expired category.
	_, err := db.Exec(
		"UPDATE keys SET exp = ? WHERE kid = ?",
		time.Now().Unix(),
		validKey.Kid,
	)
	if err != nil {
		t.Fatal(err)
	}

	validKeys, err := readKeys(db, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(validKeys) != 0 {
		t.Error("A key expiring now should not be valid")
	}

	expiredKeys, err := readKeys(db, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(expiredKeys) != 2 {
		t.Errorf("Expected 2 expired keys, got %d", len(expiredKeys))
	}

	// Initialization should create a replacement valid key.
	if err := initializeKeys(); err != nil {
		t.Fatal(err)
	}

	if !validKey.ExpiresAt.After(time.Now()) {
		t.Error("Replacement key should be valid")
	}
}
