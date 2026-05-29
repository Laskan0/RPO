package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"transport_api/internal/models"
)

type TransactionRepository struct {
	db *sql.DB
}

func NewTransactionRepository(db *sql.DB) *TransactionRepository {
	return &TransactionRepository{
		db: db,
	}
}

func (r *TransactionRepository) List(ctx context.Context) ([]models.Transaction, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
		    id,
		    terminal_id,
		    card_id,
		    terminal_serial,
		    card_number,
		    amount,
		    status,
		    balance_before,
		    balance_after,
		    message,
		    created_at
		FROM transactions
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	transactions := make([]models.Transaction, 0)

	for rows.Next() {
		transaction, err := scanTransaction(rows)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, transaction)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate transactions: %w", err)
	}

	return transactions, nil
}

func (r *TransactionRepository) FindByID(ctx context.Context, id int64) (*models.Transaction, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
		    id,
		    terminal_id,
		    card_id,
		    terminal_serial,
		    card_number,
		    amount,
		    status,
		    balance_before,
		    balance_after,
		    message,
		    created_at
		FROM transactions
		WHERE id = ?
	`, id)

	transaction, err := scanTransaction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &transaction, nil
}

type transactionScanner interface {
	Scan(dest ...any) error
}

func scanTransaction(scanner transactionScanner) (models.Transaction, error) {
	var transaction models.Transaction
	var balanceBefore sql.NullInt64
	var balanceAfter sql.NullInt64

	err := scanner.Scan(
		&transaction.ID,
		&transaction.TerminalID,
		&transaction.CardID,
		&transaction.TerminalSerial,
		&transaction.CardNumber,
		&transaction.Amount,
		&transaction.Status,
		&balanceBefore,
		&balanceAfter,
		&transaction.Message,
		&transaction.CreatedAt,
	)

	if err != nil {
		return transaction, err
	}

	if balanceBefore.Valid {
		transaction.BalanceBefore = &balanceBefore.Int64
	}

	if balanceAfter.Valid {
		transaction.BalanceAfter = &balanceAfter.Int64
	}

	return transaction, nil
}
