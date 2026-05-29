-- +goose Up
ALTER TABLE cards ADD COLUMN key_id INTEGER REFERENCES keys(id);

-- +goose Down
-- SQLite rollback intentionally left empty for lab project.
