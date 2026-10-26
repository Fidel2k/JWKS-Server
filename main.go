package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func newRouter(store *keyStore) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/.well-known/jwks.json", store.jwksHandler)
	mux.HandleFunc("/auth", store.authHandler)
	return mux
}

func main() {
	store, err := openKeyStore(databaseFile)
	if err != nil {
		log.Fatal(err)
	}
	defer store.db.Close()
	if err := store.initializeKeys(); err != nil {
		log.Print(err)
		return
	}
	fmt.Println("Server running on http://localhost:8080")
	server := &http.Server{Addr: ":8080", Handler: newRouter(store), ReadHeaderTimeout: 5 * time.Second}
	log.Print(server.ListenAndServe())
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintln(w, "JWKS Server is running!")
}
