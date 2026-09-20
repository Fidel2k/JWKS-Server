package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

var validKey *KeyPair
var expiredKey *KeyPair

func initializeKeys() error {
	var err error

	validKey, err = generateKeyPair(
		"valid-key",
		time.Now().Add(1*time.Hour),
	)
	if err != nil {
		return err
	}

	expiredKey, err = generateKeyPair(
		"expired-key",
		time.Now().Add(-1*time.Hour),
	)
	if err != nil {
		return err
	}

	return nil
}

func newRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("/auth", authHandler)

	return mux
}

func main() {
	err := initializeKeys()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Server running on http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", newRouter()))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "JWKS Server is running!")
}