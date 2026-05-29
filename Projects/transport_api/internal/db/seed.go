package db

import (
	"database/sql"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func SeedDemoData(database *sql.DB) error {
	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	terminalID, err := seedDemoTerminal(tx)
	if err != nil {
		return err
	}

	keyID, err := seedDemoGlobalMifareKey(tx)
	if err != nil {
		return err
	}

	if err := seedDemoCard(tx, keyID); err != nil {
		return err
	}

	if err := seedDemoTerminalKey(tx, terminalID); err != nil {
		return err
	}

	return tx.Commit()
}

func seedDemoTerminal(tx *sql.Tx) (int64, error) {
	var id int64

	err := tx.QueryRow(`
		SELECT id
		FROM terminals
		WHERE serial = ?
	`, "TERM-001").Scan(&id)

	if err == nil {
		return id, nil
	}

	if err != sql.ErrNoRows {
		return 0, err
	}

	res, err := tx.Exec(`
		INSERT INTO terminals (serial, name, location, is_active)
		VALUES (?, ?, ?, ?)
	`, "TERM-001", "PN532 terminal", "MacBook lab", true)

	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

func seedDemoGlobalMifareKey(tx *sql.Tx) (int64, error) {
	var id int64

	err := tx.QueryRow(`
		SELECT id
		FROM "keys"
		WHERE key_type = ?
		  AND key_value = ?
		  AND terminal_id IS NULL
	`, "mifare", "FFFFFFFFFFFF").Scan(&id)

	if err == nil {
		return id, nil
	}

	if err != sql.ErrNoRows {
		return 0, err
	}

	res, err := tx.Exec(`
		INSERT INTO "keys" (name, key_type, key_value, key_version, terminal_id, is_active)
		VALUES (?, ?, ?, ?, NULL, ?)
	`, "Default MIFARE Key A", "mifare", "FFFFFFFFFFFF", 1, true)

	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

func seedDemoCard(tx *sql.Tx, keyID int64) error {
	var id int64

	err := tx.QueryRow(`
		SELECT id
		FROM cards
		WHERE card_number = ?
	`, "b754105e").Scan(&id)

	if err == nil {
		_, err = tx.Exec(`
			UPDATE cards
			SET key_id = ?
			WHERE id = ?
			  AND key_id IS NULL
		`, keyID, id)

		return err
	}

	if err != sql.ErrNoRows {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO cards (card_number, owner_name, balance, is_blocked, key_id)
		VALUES (?, ?, ?, ?, ?)
	`, "b754105e", "Test Passenger", 500, false, keyID)

	return err
}

func seedDemoTerminalKey(tx *sql.Tx, terminalID int64) error {
	var id int64

	err := tx.QueryRow(`
		SELECT id
		FROM keys
		WHERE key_type = ?
		  AND key_value = ?
		  AND terminal_id = ?
	`, "terminal", "TERM001SECRET", terminalID).Scan(&id)

	if err == nil {
		return nil
	}

	if err != sql.ErrNoRows {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO keys (name, key_type, key_value, key_version, terminal_id, is_active)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "TERM-001 terminal key", "terminal", "TERM001SECRET", 1, terminalID, true)

	return err
}

func SeedAdmin(database *sql.DB) (bool, error) {
	username := getSeedEnv("ADMIN_USERNAME", "admin")
	password := getSeedEnv("ADMIN_PASSWORD", "admin123")

	var count int

	err := database.QueryRow(`
		SELECT COUNT(*)
		FROM users
		WHERE role = 'admin'
	`).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}

	if count > 0 {
		return false, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("hash admin password: %w", err)
	}

	_, err = database.Exec(`
		INSERT INTO users (username, password_hash, role)
		VALUES (?, ?, 'admin')
	`, username, string(hash))

	if err != nil {
		return false, fmt.Errorf("insert admin user: %w", err)
	}

	return true, nil
}

func getSeedEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
