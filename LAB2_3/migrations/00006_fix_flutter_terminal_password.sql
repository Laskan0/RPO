-- +goose Up
UPDATE users
SET password_hash = '$2b$12$RQeuahHrQC9ikp.yenoLq.fFK/4J0mWyEAchr2Hyv4neRvDs8pCGC'
WHERE login = 'flutter_terminal';

-- +goose Down
UPDATE users
SET password_hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
WHERE login = 'flutter_terminal';
