-- +goose Up
CREATE TABLE IF NOT EXISTS "keys" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'mifare' CHECK (key_type IN ('mifare', 'terminal', 'system')),
    key_value TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    terminal_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (terminal_id) REFERENCES terminals(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_terminal_id ON "keys"(terminal_id);
CREATE INDEX IF NOT EXISTS idx_keys_is_active ON "keys"(is_active);
CREATE INDEX IF NOT EXISTS idx_keys_key_type ON "keys"(key_type);

-- +goose Down
DROP TABLE IF EXISTS "keys";