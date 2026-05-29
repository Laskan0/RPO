-- +goose Up
INSERT INTO users (login, full_name, password_hash, is_admin)
SELECT 'viewer', 'Read Only User', '$2b$12$RQeuahHrQC9ikp.yenoLq.fFK/4J0mWyEAchr2Hyv4neRvDs8pCGC', 0
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE login = 'viewer'
);

-- +goose Down
DELETE FROM users WHERE login = 'viewer';
