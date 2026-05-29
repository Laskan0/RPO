package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// SQLiteDB stores the sql.DB connection so application setup stays easy to follow.
type SQLiteDB struct {
	DB *sql.DB
}

func NewSQLite(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	return &SQLiteDB{DB: db}, nil
}

func (db *SQLiteDB) Close() error {
	return db.DB.Close()
}
