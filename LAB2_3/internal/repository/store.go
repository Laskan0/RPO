package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"lab2/internal/model"
)

// Store groups repository methods in one simple structure.
// This keeps the app easy to read while still separating SQL from handlers.
type Store struct {
	db *sql.DB
}

var (
	ErrCardBlocked         = errors.New("card is blocked")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrTerminalInactive    = errors.New("terminal is inactive")
)

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) ListKeys(ctx context.Context) ([]model.Key, error) {
	items := make([]model.Key, 0)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, value, description, created_at
		FROM keys
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item model.Key
		if err := rows.Scan(&item.ID, &item.Name, &item.Value, &item.Description, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan key: %w", err)
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (s *Store) GetKeyByID(ctx context.Context, id int64) (*model.Key, error) {
	var item model.Key

	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, value, description, created_at
		FROM keys
		WHERE id = ?
	`, id).Scan(&item.ID, &item.Name, &item.Value, &item.Description, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) CreateKey(ctx context.Context, item model.Key) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO keys (name, value, description)
		VALUES (?, ?, ?)
	`, item.Name, item.Value, item.Description)
	if err != nil {
		return 0, fmt.Errorf("create key: %w", err)
	}

	return result.LastInsertId()
}

func (s *Store) UpdateKey(ctx context.Context, item model.Key) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE keys
		SET name = ?, value = ?, description = ?
		WHERE id = ?
	`, item.Name, item.Value, item.Description, item.ID)
	if err != nil {
		return fmt.Errorf("update key: %w", err)
	}

	return nil
}

func (s *Store) DeleteKey(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete key transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `DELETE FROM transactions WHERE card_id IN (SELECT id FROM cards WHERE key_id = ?)`, id)
	if err != nil {
		return fmt.Errorf("delete key transactions: %w", err)
	}

	_ = result

	if _, err := tx.ExecContext(ctx, `DELETE FROM cards WHERE key_id = ?`, id); err != nil {
		return fmt.Errorf("delete key cards: %w", err)
	}

	result, err = tx.ExecContext(ctx, `DELETE FROM keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete key: %w", err)
	}

	if err := checkDeletedRows(result); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete key transaction: %w", err)
	}

	return nil
}

func (s *Store) ListTerminals(ctx context.Context) ([]model.Terminal, error) {
	items := make([]model.Terminal, 0)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, serial_number, name, address, is_active, created_at
		FROM terminals
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list terminals: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item model.Terminal
		if err := rows.Scan(&item.ID, &item.SerialNumber, &item.Name, &item.Address, &item.IsActive, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan terminal: %w", err)
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (s *Store) GetTerminalByID(ctx context.Context, id int64) (*model.Terminal, error) {
	var item model.Terminal

	err := s.db.QueryRowContext(ctx, `
		SELECT id, serial_number, name, address, is_active, created_at
		FROM terminals
		WHERE id = ?
	`, id).Scan(&item.ID, &item.SerialNumber, &item.Name, &item.Address, &item.IsActive, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) GetTerminalBySerialNumber(ctx context.Context, serialNumber string) (*model.Terminal, error) {
	var item model.Terminal

	err := s.db.QueryRowContext(ctx, `
		SELECT id, serial_number, name, address, is_active, created_at
		FROM terminals
		WHERE serial_number = ?
	`, serialNumber).Scan(&item.ID, &item.SerialNumber, &item.Name, &item.Address, &item.IsActive, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) CreateTerminal(ctx context.Context, item model.Terminal) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO terminals (serial_number, name, address, is_active)
		VALUES (?, ?, ?, ?)
	`, item.SerialNumber, item.Name, item.Address, item.IsActive)
	if err != nil {
		return 0, fmt.Errorf("create terminal: %w", err)
	}

	return result.LastInsertId()
}

func (s *Store) UpdateTerminal(ctx context.Context, item model.Terminal) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE terminals
		SET serial_number = ?, name = ?, address = ?, is_active = ?
		WHERE id = ?
	`, item.SerialNumber, item.Name, item.Address, item.IsActive, item.ID)
	if err != nil {
		return fmt.Errorf("update terminal: %w", err)
	}

	return nil
}

func (s *Store) DeleteTerminal(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete terminal transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM transactions WHERE terminal_id = ?`, id); err != nil {
		return fmt.Errorf("delete terminal transactions: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM terminals WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete terminal: %w", err)
	}

	if err := checkDeletedRows(result); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete terminal transaction: %w", err)
	}

	return nil
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	items := make([]model.User, 0)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, login, full_name, password_hash, is_admin, created_at
		FROM users
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item model.User
		if err := rows.Scan(&item.ID, &item.Login, &item.FullName, &item.PasswordHash, &item.IsAdmin, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*model.User, error) {
	var item model.User

	err := s.db.QueryRowContext(ctx, `
		SELECT id, login, full_name, password_hash, is_admin, created_at
		FROM users
		WHERE id = ?
	`, id).Scan(&item.ID, &item.Login, &item.FullName, &item.PasswordHash, &item.IsAdmin, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) GetUserByLogin(ctx context.Context, login string) (*model.User, error) {
	var item model.User

	err := s.db.QueryRowContext(ctx, `
		SELECT id, login, full_name, password_hash, is_admin, created_at
		FROM users
		WHERE login = ?
	`, login).Scan(&item.ID, &item.Login, &item.FullName, &item.PasswordHash, &item.IsAdmin, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) CreateUser(ctx context.Context, item model.User) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO users (login, full_name, password_hash, is_admin)
		VALUES (?, ?, ?, ?)
	`, item.Login, item.FullName, item.PasswordHash, item.IsAdmin)
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}

	return result.LastInsertId()
}

func (s *Store) UpdateUser(ctx context.Context, item model.User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET login = ?, full_name = ?, password_hash = ?, is_admin = ?
		WHERE id = ?
	`, item.Login, item.FullName, item.PasswordHash, item.IsAdmin, item.ID)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	return checkDeletedRows(result)
}

func (s *Store) ListCards(ctx context.Context) ([]model.Card, error) {
	items := make([]model.Card, 0)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at
		FROM cards
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list cards: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item model.Card
		if err := rows.Scan(&item.ID, &item.CardNumber, &item.OwnerName, &item.Balance, &item.IsBlocked, &item.KeyID, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan card: %w", err)
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (s *Store) GetCardByID(ctx context.Context, id int64) (*model.Card, error) {
	var item model.Card

	err := s.db.QueryRowContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at
		FROM cards
		WHERE id = ?
	`, id).Scan(&item.ID, &item.CardNumber, &item.OwnerName, &item.Balance, &item.IsBlocked, &item.KeyID, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) GetCardByNumber(ctx context.Context, cardNumber string) (*model.Card, error) {
	var item model.Card

	err := s.db.QueryRowContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at
		FROM cards
		WHERE card_number = ?
	`, cardNumber).Scan(&item.ID, &item.CardNumber, &item.OwnerName, &item.Balance, &item.IsBlocked, &item.KeyID, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) CreateCard(ctx context.Context, item model.Card) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO cards (card_number, owner_name, balance, is_blocked, key_id)
		VALUES (?, ?, ?, ?, ?)
	`, item.CardNumber, item.OwnerName, item.Balance, item.IsBlocked, item.KeyID)
	if err != nil {
		return 0, fmt.Errorf("create card: %w", err)
	}

	return result.LastInsertId()
}

func (s *Store) UpdateCard(ctx context.Context, item model.Card) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE cards
		SET card_number = ?, owner_name = ?, balance = ?, is_blocked = ?, key_id = ?
		WHERE id = ?
	`, item.CardNumber, item.OwnerName, item.Balance, item.IsBlocked, item.KeyID, item.ID)
	if err != nil {
		return fmt.Errorf("update card: %w", err)
	}

	return nil
}

func (s *Store) DeleteCard(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete card transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM transactions WHERE card_id = ?`, id); err != nil {
		return fmt.Errorf("delete card transactions: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM cards WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete card: %w", err)
	}

	if err := checkDeletedRows(result); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete card transaction: %w", err)
	}

	return nil
}

func (s *Store) ListTransactions(ctx context.Context) ([]model.Transaction, error) {
	items := make([]model.Transaction, 0)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, amount, card_id, terminal_id, authorized, created_at
		FROM transactions
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item model.Transaction
		if err := rows.Scan(&item.ID, &item.Amount, &item.CardID, &item.TerminalID, &item.Authorized, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (s *Store) GetTransactionByID(ctx context.Context, id int64) (*model.Transaction, error) {
	var item model.Transaction

	err := s.db.QueryRowContext(ctx, `
		SELECT id, amount, card_id, terminal_id, authorized, created_at
		FROM transactions
		WHERE id = ?
	`, id).Scan(&item.ID, &item.Amount, &item.CardID, &item.TerminalID, &item.Authorized, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func (s *Store) CreateTransaction(ctx context.Context, item model.Transaction) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO transactions (amount, card_id, terminal_id, authorized)
		VALUES (?, ?, ?, ?)
	`, item.Amount, item.CardID, item.TerminalID, item.Authorized)
	if err != nil {
		return 0, fmt.Errorf("create transaction: %w", err)
	}

	return result.LastInsertId()
}

func (s *Store) UpdateTransaction(ctx context.Context, item model.Transaction) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE transactions
		SET amount = ?, card_id = ?, terminal_id = ?, authorized = ?
		WHERE id = ?
	`, item.Amount, item.CardID, item.TerminalID, item.Authorized, item.ID)
	if err != nil {
		return fmt.Errorf("update transaction: %w", err)
	}

	return nil
}

func (s *Store) DeleteTransaction(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM transactions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete transaction: %w", err)
	}

	return checkDeletedRows(result)
}

func checkDeletedRows(result sql.Result) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deleted rows: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) AuthorizePayment(ctx context.Context, serialNumber string, cardNumber string, amount int64) (*model.Transaction, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var terminal model.Terminal
	err = tx.QueryRowContext(ctx, `
		SELECT id, serial_number, name, address, is_active, created_at
		FROM terminals
		WHERE serial_number = ?
	`, serialNumber).Scan(&terminal.ID, &terminal.SerialNumber, &terminal.Name, &terminal.Address, &terminal.IsActive, &terminal.CreatedAt)
	if err != nil {
		return nil, "", err
	}

	if !terminal.IsActive {
		return nil, "", ErrTerminalInactive
	}

	var card model.Card
	err = tx.QueryRowContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at
		FROM cards
		WHERE card_number = ?
	`, cardNumber).Scan(&card.ID, &card.CardNumber, &card.OwnerName, &card.Balance, &card.IsBlocked, &card.KeyID, &card.CreatedAt)
	if err != nil {
		return nil, "", err
	}

	authorized := false
	reason := ""

	switch {
	case card.IsBlocked:
		reason = ErrCardBlocked.Error()
	case card.Balance < amount:
		reason = ErrInsufficientBalance.Error()
	default:
		authorized = true
		reason = "authorized"
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO transactions (amount, card_id, terminal_id, authorized)
		VALUES (?, ?, ?, ?)
	`, amount, card.ID, terminal.ID, authorized)
	if err != nil {
		return nil, "", fmt.Errorf("create authorization transaction: %w", err)
	}

	transactionID, err := result.LastInsertId()
	if err != nil {
		return nil, "", fmt.Errorf("get authorization transaction id: %w", err)
	}

	if authorized {
		_, err = tx.ExecContext(ctx, `
			UPDATE cards
			SET balance = balance - ?
			WHERE id = ?
		`, amount, card.ID)
		if err != nil {
			return nil, "", fmt.Errorf("update card balance: %w", err)
		}
	}

	var transaction model.Transaction
	err = tx.QueryRowContext(ctx, `
		SELECT id, amount, card_id, terminal_id, authorized, created_at
		FROM transactions
		WHERE id = ?
	`, transactionID).Scan(&transaction.ID, &transaction.Amount, &transaction.CardID, &transaction.TerminalID, &transaction.Authorized, &transaction.CreatedAt)
	if err != nil {
		return nil, "", fmt.Errorf("load created authorization transaction: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit authorization transaction: %w", err)
	}

	return &transaction, reason, nil
}

type DatabaseSummary struct {
	KeysCount         int `json:"keys_count"`
	TerminalsCount    int `json:"terminals_count"`
	UsersCount        int `json:"users_count"`
	CardsCount        int `json:"cards_count"`
	TransactionsCount int `json:"transactions_count"`
}

func (s *Store) Summary(ctx context.Context) (DatabaseSummary, error) {
	return DatabaseSummary{
		KeysCount:         s.countRows(ctx, "keys"),
		TerminalsCount:    s.countRows(ctx, "terminals"),
		UsersCount:        s.countRows(ctx, "users"),
		CardsCount:        s.countRows(ctx, "cards"),
		TransactionsCount: s.countRows(ctx, "transactions"),
	}, nil
}

func (s *Store) countRows(ctx context.Context, table string) int {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", table)

	var count int
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0
	}

	return count
}
