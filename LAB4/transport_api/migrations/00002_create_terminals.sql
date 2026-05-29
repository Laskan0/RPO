-- +goose Up
CREATE TABLE IF NOT EXISTS terminals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    location TEXT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_terminals_serial ON terminals(serial);
CREATE INDEX IF NOT EXISTS idx_terminals_is_active ON terminals(is_active);

-- +goose Down
DROP TABLE IF EXISTS terminals;