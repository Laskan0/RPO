-- +goose Up
INSERT INTO keys (name, value, description)
VALUES
    ('BASE_KEY_A', 'A0A1A2A3A4A5', 'Основной ключ для первой группы карт'),
    ('BASE_KEY_B', 'B0B1B2B3B4B5', 'Основной ключ для второй группы карт');

INSERT INTO terminals (serial_number, name, address, is_active)
VALUES
    ('TERM-1001', 'Терминал метро', 'г. Москва, станция Центральная', 1),
    ('TERM-1002', 'Терминал автобуса', 'г. Москва, маршрут A12', 1);

INSERT INTO users (login, full_name, password_hash, is_admin)
VALUES
    ('admin', 'System Administrator', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 1),
    ('operator', 'Transport Operator', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 0);

INSERT INTO cards (card_number, owner_name, balance, is_blocked, key_id)
VALUES
    ('CARD-0001', 'Иван Петров', 15000, 0, 1),
    ('CARD-0002', 'Мария Соколова', 3200, 0, 1),
    ('CARD-0003', 'Алексей Смирнов', 0, 1, 2);

INSERT INTO transactions (amount, card_id, terminal_id, authorized)
VALUES
    (65, 1, 1, 1),
    (65, 2, 2, 1),
    (65, 3, 1, 0);

-- +goose Down
DELETE FROM transactions;
DELETE FROM cards;
DELETE FROM users;
DELETE FROM terminals;
DELETE FROM keys;
