package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

var validKey *KeyPair
var expiredKey *KeyPair

func main() {
	var err error

	validKey, err = generateKeyPair(
		"valid-key",
		time.Now().Add(1*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	expiredKey, err = generateKeyPair(
		"expired-key",
		time.Now().Add(-1*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	fmt.Println("Server running on http://localhost:8080")

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "JWKS Server is running!")
}