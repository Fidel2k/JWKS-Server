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

const databaseFile = "totally_not_my_privateKeys.db"

type keyStore struct{ db *sql.DB }

func openKeyStore(path string) (*keyStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
 kid INTEGER PRIMARY KEY AUTOINCREMENT,
 key BLOB NOT NULL,
 exp INTEGER NOT NULL
 )`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &keyStore{db: db}, nil
}

// Values are bound separately from SQL so they cannot become SQL commands.
func (s *keyStore) save(key *KeyPair) error {
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.PrivateKey)})
	result, err := s.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", data, key.ExpiresAt.Unix())
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	key.Kid = strconv.FormatInt(id, 10)
	return err
}

func (s *keyStore) read(expired bool, now int64) ([]*KeyPair, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid"
	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid"
	}
	rows, err := s.db.Query(query, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []*KeyPair{}
	for rows.Next() {
		var id, exp int64
		var data []byte
		if err := rows.Scan(&id, &data, &exp); err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid PEM for key %d", id)
		}
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &KeyPair{PrivateKey: privateKey, Kid: strconv.FormatInt(id, 10), ExpiresAt: time.Unix(exp, 0)})
	}
	return keys, rows.Err()
}

// Reuse saved keys on restart, adding a key only when a category is missing.
func (s *keyStore) initializeKeys() error {
	now := time.Now()
	for _, expired := range []bool{false, true} {
		keys, err := s.read(expired, now.Unix())
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			continue
		}
		expiration := now.Add(time.Hour)
		if expired {
			expiration = now.Add(-time.Hour)
		}
		key, err := generateKeyPair("", expiration)
		if err != nil {
			return err
		}
		if err := s.save(key); err != nil {
			return err
		}
	}
	return nil
}
