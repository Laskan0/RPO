package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"transport_api/internal/models"
)

type CardRepository struct {
	db *sql.DB
}

func NewCardRepository(db *sql.DB) *CardRepository {
	return &CardRepository{
		db: db,
	}
}

func (r *CardRepository) List(ctx context.Context) ([]models.Card, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at, updated_at
		FROM cards
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list cards: %w", err)
	}
	defer rows.Close()

	cards := make([]models.Card, 0)

	for rows.Next() {
		card, err := scanCard(rows)
		if err != nil {
			return nil, err
		}

		cards = append(cards, card)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cards: %w", err)
	}

	return cards, nil
}

func (r *CardRepository) FindByID(ctx context.Context, id int64) (*models.Card, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at, updated_at
		FROM cards
		WHERE id = ?
	`, id)

	card, err := scanCard(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &card, nil
}

func (r *CardRepository) FindByNumber(ctx context.Context, cardNumber string) (*models.Card, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, card_number, owner_name, balance, is_blocked, key_id, created_at, updated_at
		FROM cards
		WHERE card_number = ?
	`, cardNumber)

	card, err := scanCard(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &card, nil
}

func (r *CardRepository) Create(ctx context.Context, card models.Card) (*models.Card, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO cards (card_number, owner_name, balance, is_blocked, key_id)
		VALUES (?, ?, ?, ?, ?)
	`,
		card.CardNumber,
		stringPtrValue(card.OwnerName),
		card.Balance,
		boolToInt(card.IsBlocked),
		int64PtrValue(card.KeyID),
	)

	if err != nil {
		return nil, fmt.Errorf("create card: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get card id: %w", err)
	}

	return r.FindByID(ctx, id)
}

func (r *CardRepository) Update(ctx context.Context, id int64, card models.Card) (*models.Card, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE cards
		SET card_number = ?,
			owner_name = ?,
			balance = ?,
			is_blocked = ?,
			key_id = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`,
		card.CardNumber,
		stringPtrValue(card.OwnerName),
		card.Balance,
		boolToInt(card.IsBlocked),
		int64PtrValue(card.KeyID),
		id,
	)

	if err != nil {
		return nil, fmt.Errorf("update card: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return nil, nil
	}

	return r.FindByID(ctx, id)
}

func (r *CardRepository) Delete(ctx context.Context, id int64) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM cards
		WHERE id = ?
	`, id)

	if err != nil {
		return false, fmt.Errorf("delete card: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

type cardScanner interface {
	Scan(dest ...any) error
}

func scanCard(scanner cardScanner) (models.Card, error) {
	var card models.Card
	var ownerName sql.NullString
	var keyID sql.NullInt64
	var isBlocked int

	err := scanner.Scan(
		&card.ID,
		&card.CardNumber,
		&ownerName,
		&card.Balance,
		&isBlocked,
		&keyID,
		&card.CreatedAt,
		&card.UpdatedAt,
	)

	if err != nil {
		return card, err
	}

	if ownerName.Valid {
		card.OwnerName = &ownerName.String
	}

	if keyID.Valid {
		card.KeyID = &keyID.Int64
	}

	card.IsBlocked = isBlocked == 1

	return card, nil
}

func stringPtrValue(value *string) any {
	if value == nil {
		return nil
	}

	return *value
}
