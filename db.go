package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

const DBFileName = "totally_not_my_privateKeys.db"

// dbKeyRow matches one row from the keys table.
type dbKeyRow struct {
	KID int64
	PEM []byte
	Exp int64
}

func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", DBFileName)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);`)
	return err
}

// ensureSeedKeys inserts one expired and one valid key if the table is empty.
func ensureSeedKeys(db *sql.DB, now time.Time) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM keys;`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	// expired: exp <= now
	if err := insertKey(db, now.Add(-1*time.Hour).Unix()); err != nil {
		return err
	}
	// valid: exp >= now + 1 hour
	return insertKey(db, now.Add(2*time.Hour).Unix())
}

func insertKey(db *sql.DB, exp int64) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	_, err = db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, pemBytes, exp)
	return err
}

func getOneValidKey(db *sql.DB, now time.Time) (dbKeyRow, error) {
	// valid = exp > now
	row := db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`,
		now.Unix(),
	)

	var r dbKeyRow
	if err := row.Scan(&r.KID, &r.PEM, &r.Exp); err != nil {
		return dbKeyRow{}, err
	}
	return r, nil
}

func getOneExpiredKey(db *sql.DB, now time.Time) (dbKeyRow, error) {
	// expired = exp <= now
	row := db.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1`,
		now.Unix(),
	)

	var r dbKeyRow
	if err := row.Scan(&r.KID, &r.PEM, &r.Exp); err != nil {
		return dbKeyRow{}, err
	}
	return r, nil
}

func getAllValidKeys(db *sql.DB, now time.Time) ([]dbKeyRow, error) {
	rows, err := db.Query(
		`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC`,
		now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []dbKeyRow
	for rows.Next() {
		var r dbKeyRow
		if err := rows.Scan(&r.KID, &r.PEM, &r.Exp); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func parseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("unexpected PEM type")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}