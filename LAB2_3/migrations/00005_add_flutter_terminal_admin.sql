-- +goose Up
INSERT INTO users (login, full_name, password_hash, is_admin)
SELECT 'flutter_terminal', 'Flutter Terminal Client', '$2b$12$RQeuahHrQC9ikp.yenoLq.fFK/4J0mWyEAchr2Hyv4neRvDs8pCGC', 1
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE login = 'flutter_terminal'
);

-- +goose Down
DELETE FROM users WHERE login = 'flutter_terminal';
