-- +goose Up
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    terminal_id INTEGER NOT NULL,
    card_id INTEGER NOT NULL,
    terminal_serial TEXT NOT NULL,
    card_number TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    status TEXT NOT NULL CHECK (status IN ('approved', 'declined')),
    balance_before INTEGER,
    balance_after INTEGER,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (terminal_id) REFERENCES terminals(id) ON DELETE RESTRICT,
    FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_transactions_terminal_id ON transactions(terminal_id);
CREATE INDEX IF NOT EXISTS idx_transactions_card_id ON transactions(card_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);

-- +goose Down
DROP TABLE IF EXISTS transactions;