package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type PaymentRepository struct {
	db *sql.DB
}

type PaymentAuthorizationInput struct {
	TerminalSerial string
	CardNumber     string
	Amount         int64
}

type PaymentAuthorizationResult struct {
	Approved      bool   `json:"approved"`
	Message       string `json:"message"`
	CardNumber    string `json:"card_number,omitempty"`
	BalanceBefore *int64 `json:"balance_before,omitempty"`
	Amount        int64  `json:"amount,omitempty"`
	BalanceAfter  *int64 `json:"balance_after,omitempty"`
	TransactionID *int64 `json:"transaction_id,omitempty"`
}

func NewPaymentRepository(db *sql.DB) *PaymentRepository {
	return &PaymentRepository{
		db: db,
	}
}

func (r *PaymentRepository) AuthorizePayment(
	ctx context.Context,
	input PaymentAuthorizationInput,
) (*PaymentAuthorizationResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin payment transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var terminalID int64
	var terminalIsActive int

	err = tx.QueryRowContext(ctx, `
		SELECT id, is_active
		FROM terminals
		WHERE serial = ?
	`, input.TerminalSerial).Scan(&terminalID, &terminalIsActive)

	if errors.Is(err, sql.ErrNoRows) {
		return &PaymentAuthorizationResult{
			Approved:   false,
			Message:    "Terminal not found",
			CardNumber: input.CardNumber,
			Amount:     input.Amount,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("find terminal: %w", err)
	}

	if terminalIsActive != 1 {
		return &PaymentAuthorizationResult{
			Approved:   false,
			Message:    "Terminal is inactive",
			CardNumber: input.CardNumber,
			Amount:     input.Amount,
		}, nil
	}

	var cardID int64
	var balance int64
	var isBlocked int

	err = tx.QueryRowContext(ctx, `
		SELECT id, balance, is_blocked
		FROM cards
		WHERE card_number = ?
	`, input.CardNumber).Scan(&cardID, &balance, &isBlocked)

	if errors.Is(err, sql.ErrNoRows) {
		return &PaymentAuthorizationResult{
			Approved:   false,
			Message:    "Card not found",
			CardNumber: input.CardNumber,
			Amount:     input.Amount,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("find card: %w", err)
	}

	if isBlocked == 1 {
		transactionID, err := insertPaymentTransaction(
			ctx,
			tx,
			terminalID,
			cardID,
			input.TerminalSerial,
			input.CardNumber,
			input.Amount,
			"declined",
			balance,
			balance,
			"Card is blocked",
		)
		if err != nil {
			return nil, err
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit blocked card transaction: %w", err)
		}
		committed = true

		return &PaymentAuthorizationResult{
			Approved:      false,
			Message:       "Card is blocked",
			CardNumber:    input.CardNumber,
			BalanceBefore: &balance,
			Amount:        input.Amount,
			BalanceAfter:  &balance,
			TransactionID: &transactionID,
		}, nil
	}

	if balance < input.Amount {
		transactionID, err := insertPaymentTransaction(
			ctx,
			tx,
			terminalID,
			cardID,
			input.TerminalSerial,
			input.CardNumber,
			input.Amount,
			"declined",
			balance,
			balance,
			"Insufficient funds",
		)
		if err != nil {
			return nil, err
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit insufficient funds transaction: %w", err)
		}
		committed = true

		return &PaymentAuthorizationResult{
			Approved:      false,
			Message:       "Insufficient funds",
			CardNumber:    input.CardNumber,
			BalanceBefore: &balance,
			Amount:        input.Amount,
			BalanceAfter:  &balance,
			TransactionID: &transactionID,
		}, nil
	}

	balanceBefore := balance
	balanceAfter := balance - input.Amount

	_, err = tx.ExecContext(ctx, `
		UPDATE cards
		SET balance = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, balanceAfter, cardID)

	if err != nil {
		return nil, fmt.Errorf("update card balance: %w", err)
	}

	transactionID, err := insertPaymentTransaction(
		ctx,
		tx,
		terminalID,
		cardID,
		input.TerminalSerial,
		input.CardNumber,
		input.Amount,
		"approved",
		balanceBefore,
		balanceAfter,
		"Transaction approved",
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit approved transaction: %w", err)
	}
	committed = true

	return &PaymentAuthorizationResult{
		Approved:      true,
		Message:       "Transaction approved",
		CardNumber:    input.CardNumber,
		BalanceBefore: &balanceBefore,
		Amount:        input.Amount,
		BalanceAfter:  &balanceAfter,
		TransactionID: &transactionID,
	}, nil
}

func insertPaymentTransaction(
	ctx context.Context,
	tx *sql.Tx,
	terminalID int64,
	cardID int64,
	terminalSerial string,
	cardNumber string,
	amount int64,
	status string,
	balanceBefore int64,
	balanceAfter int64,
	message string,
) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO transactions (
		    terminal_id,
		    card_id,
		    terminal_serial,
		    card_number,
		    amount,
		    status,
		    balance_before,
		    balance_after,
		    message
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		terminalID,
		cardID,
		terminalSerial,
		cardNumber,
		amount,
		status,
		balanceBefore,
		balanceAfter,
		message,
	)

	if err != nil {
		return 0, fmt.Errorf("insert payment transaction: %w", err)
	}

	transactionID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get transaction id: %w", err)
	}

	return transactionID, nil
}
