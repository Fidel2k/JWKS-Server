package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"
)

//hold key valid and expired so handler can use
var validKey *KeyPair
var expiredKey *KeyPair
var db *sql.DB

//creates one valid key and one expired key when program starts
// Reuses saved keys and creates missing keys.
func initializeKeys() error {
	keys, err := readKeys(db, false)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		validKey = keys[len(keys)-1]
	} else {
		validKey, err = generateKeyPair(
			"",
			time.Now().Add(time.Hour),
		)
		if err != nil {
			return err
		}

		if err := saveKey(db, validKey); err != nil {
			return err
		}
	}

	keys, err = readKeys(db, true)
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		expiredKey = keys[len(keys)-1]
	} else {
		expiredKey, err = generateKeyPair(
			"",
			time.Now().Add(-time.Hour),
		)
		if err != nil {
			return err
		}

		if err := saveKey(db, expiredKey); err != nil {
			return err
		}
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
	var err error

	db, err = openDatabase("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := initializeKeys(); err != nil {
		log.Print(err)
		return
	}

	fmt.Println("Server running on http://localhost:8080")

	if err := http.ListenAndServe(":8080", newRouter()); err != nil {
		log.Print(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "JWKS Server is running!")
}
