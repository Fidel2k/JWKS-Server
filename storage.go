package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// Opens the database and creates the keys table.
func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// Converts a private key to PEM and saves it in the database.
func saveKey(db *sql.DB, key *KeyPair) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key.PrivateKey)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Placeholders keep the values separate from the SQL command.
	result, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		keyPEM,
		key.ExpiresAt.Unix(),
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	key.Kid = strconv.FormatInt(id, 10)
	return nil
}

// Converts stored PEM data back into an RSA private key.
func decodeKey(data []byte) (*KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PrivateKey: privateKey}, nil
}

// Reads either expired or valid keys from the database.
func readKeys(db *sql.DB, expired bool) ([]*KeyPair, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid"

	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid"
	}

	rows, err := db.Query(query, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []*KeyPair{}

	for rows.Next() {
		var id int64
		var data []byte
		var expiration int64

		err := rows.Scan(&id, &data, &expiration)
		if err != nil {
			return nil, err
		}

		key, err := decodeKey(data)
		if err != nil {
			return nil, err
		}

		key.Kid = strconv.FormatInt(id, 10)
		key.ExpiresAt = time.Unix(expiration, 0)

		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}
