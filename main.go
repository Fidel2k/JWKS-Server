package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)
//hold key valid and expired so handler can use
var validKey *KeyPair
var expiredKey *KeyPair
//creates one valid key and one expired key when program starts 
func initializeKeys() error {
	var err error
	//key expires in 1hr
	validKey, err = generateKeyPair(
		"valid-key",
		time.Now().Add(1*time.Hour),
	)
	if err != nil {
		return err
	}
	//expired key 1hr ago
	expiredKey, err = generateKeyPair(
		"expired-key",
		time.Now().Add(-1*time.Hour),
	)
	if err != nil {
		return err
	}

	return nil
}
//setup all routs for server
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("/auth", authHandler)

	return mux
}

func main() {
	//generate the key before starting the server
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