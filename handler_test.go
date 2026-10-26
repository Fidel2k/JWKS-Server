package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testStore(t *testing.T) *keyStore {
	t.Helper()
	s, err := openKeyStore(filepath.Join(t.TempDir(), databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	if err := s.initializeKeys(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthAndJWKS(t *testing.T) {
	s := testStore(t)
	router := newRouter(s)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	var jwks JWKS
	if err := json.Unmarshal(response.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || len(jwks.Keys) != 1 {
		t.Fatalf("unexpected JWKS: %s", response.Body)
	}
	jwk := jwks.Keys[0]
	n, _ := base64.RawURLEncoding.DecodeString(jwk.N)
	e, _ := base64.RawURLEncoding.DecodeString(jwk.E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	for _, path := range []string{"/auth", "/auth?expired", "/auth?expired=true", "/auth?expired=false"} {
		for _, basic := range []bool{false, true} {
			req := httptest.NewRequest("POST", path, strings.NewReader(`{"username":"userABC","password":"password123"}`))
			if basic {
				req.SetBasicAuth("userABC", "password123")
			}
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			if res.Code != 200 {
				t.Fatalf("auth failed: %s", res.Body)
			}
			expired := strings.Contains(path, "?")
			keys, err := s.read(expired, time.Now().Unix())
			if err != nil {
				t.Fatal(err)
			}
			verificationKey := pub
			if expired {
				verificationKey = &keys[0].PrivateKey.PublicKey
			}
			token, err := jwt.Parse(res.Body.String(), func(token *jwt.Token) (interface{}, error) { return verificationKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
			if expired {
				if !errors.Is(err, jwt.ErrTokenExpired) {
					t.Fatalf("expected expired token: %v", err)
				}
			} else if err != nil || !token.Valid {
				t.Fatalf("invalid signature: %v", err)
			}
			if token.Header["kid"] != keys[0].Kid {
				t.Fatal("JWT kid does not match database")
			}
			if token.Claims.(jwt.MapClaims)["sub"] != "userABC" {
				t.Fatal("wrong subject")
			}
		}
	}
}

func TestRoutesAndMethods(t *testing.T) {
	router := newRouter(testStore(t))
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/", 200}, {"GET", "/missing", 404}, {"GET", "/auth", 405}, {"POST", "/.well-known/jwks.json", 405}, {"PUT", "/auth", 405}, {"DELETE", "/.well-known/jwks.json", 405},
	} {
		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, nil))
		if res.Code != tc.status {
			t.Errorf("%s %s: %d", tc.method, tc.path, res.Code)
		}
	}
}

func TestPersistenceAndAllValidKeys(t *testing.T) {
	s := testStore(t)
	original, err := s.read(false, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	var path string
	var seq int
	var name string
	if err := s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	reopened, err := openKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	if err := reopened.initializeKeys(); err != nil {
		t.Fatal(err)
	}
	saved, err := reopened.read(false, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || saved[0].Kid != original[0].Kid || !saved[0].PrivateKey.Equal(original[0].PrivateKey) {
		t.Fatal("key changed after restart")
	}
	extra, err := generateKeyPair("", time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.save(extra); err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	reopened.jwksHandler(res, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	var jwks JWKS
	if err := json.Unmarshal(res.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 || jwks.Keys[0].Kid == jwks.Keys[1].Kid {
		t.Fatal("missing keys or duplicate IDs")
	}
}

func TestDatabaseFailuresAndEmptyResults(t *testing.T) {
	s := testStore(t)
	if _, err := s.db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	s.authHandler(res, httptest.NewRequest("POST", "/auth", nil))
	if res.Code != 500 {
		t.Fatal("missing key should fail")
	}
	res = httptest.NewRecorder()
	s.jwksHandler(res, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"keys":[]`) {
		t.Fatal("expected empty JWKS array")
	}
	s.db.Close()
	if err := s.initializeKeys(); err == nil {
		t.Fatal("closed DB should fail")
	}
	key, err := generateKeyPair("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.save(key); err == nil {
		t.Fatal("closed DB write should fail")
	}
	for _, path := range []string{"/auth", "/.well-known/jwks.json"} {
		method := "GET"
		if path == "/auth" {
			method = "POST"
		}
		res := httptest.NewRecorder()
		newRouter(s).ServeHTTP(res, httptest.NewRequest(method, path, nil))
		if res.Code != 500 {
			t.Fatal("closed DB request should fail")
		}
	}
	if _, err := openKeyStore(filepath.Join(t.TempDir(), "missing", "db")); err == nil {
		t.Fatal("bad path should fail")
	}
}

func TestInvalidStoredKeysAndExpiryBoundary(t *testing.T) {
	for _, data := range []string{"'; DROP TABLE keys; --", "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----"} {
		s := testStore(t)
		if _, err := s.db.Exec("DELETE FROM keys"); err != nil {
			t.Fatal(err)
		}
		now := time.Now().Unix()
		if _, err := s.db.Exec("INSERT INTO keys(key,exp) VALUES (?,?)", []byte(data), now); err != nil {
			t.Fatal(err)
		}
		valid, err := s.read(false, now)
		if err != nil || len(valid) != 0 {
			t.Fatal("exp == now must be expired")
		}
		if _, err := s.read(true, now); err == nil {
			t.Fatal("bad key should fail parsing")
		}
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil || count != 1 {
			t.Fatal("SQL text changed the table")
		}
	}
}
