package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"transport_api/internal/models"
)

var (
	ErrTerminalNotFound = errors.New("terminal not found")
	ErrTerminalInactive = errors.New("terminal is inactive")
)

type KeyRepository struct {
	db *sql.DB
}

func NewKeyRepository(db *sql.DB) *KeyRepository {
	return &KeyRepository{
		db: db,
	}
}

func (r *KeyRepository) List(ctx context.Context) ([]models.Key, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
		    id,
		    name,
		    key_type,
		    key_value,
		    key_version,
		    terminal_id,
		    is_active,
		    created_by,
		    created_at,
		    updated_at
		FROM "keys"
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	keys := make([]models.Key, 0)

	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate keys: %w", err)
	}

	return keys, nil
}

func (r *KeyRepository) FindByID(ctx context.Context, id int64) (*models.Key, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
		    id,
		    name,
		    key_type,
		    key_value,
		    key_version,
		    terminal_id,
		    is_active,
		    created_by,
		    created_at,
		    updated_at
		FROM "keys"
		WHERE id = ?
	`, id)

	key, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &key, nil
}

func (r *KeyRepository) Create(ctx context.Context, key models.Key) (*models.Key, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO "keys" (
		    name,
		    key_type,
		    key_value,
		    key_version,
		    terminal_id,
		    is_active,
		    created_by
		)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		key.Name,
		key.KeyType,
		key.KeyValue,
		key.KeyVersion,
		int64PtrValue(key.TerminalID),
		boolToInt(key.IsActive),
		int64PtrValue(key.CreatedBy),
	)

	if err != nil {
		return nil, fmt.Errorf("create key: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get key id: %w", err)
	}

	return r.FindByID(ctx, id)
}

func (r *KeyRepository) Update(ctx context.Context, id int64, key models.Key) (*models.Key, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE "keys"
		SET name = ?,
		    key_type = ?,
		    key_value = ?,
		    key_version = ?,
		    terminal_id = ?,
		    is_active = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`,
		key.Name,
		key.KeyType,
		key.KeyValue,
		key.KeyVersion,
		int64PtrValue(key.TerminalID),
		boolToInt(key.IsActive),
		id,
	)

	if err != nil {
		return nil, fmt.Errorf("update key: %w", err)
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

func (r *KeyRepository) Delete(ctx context.Context, id int64) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM "keys"
		WHERE id = ?
	`, id)

	if err != nil {
		return false, fmt.Errorf("delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

func (r *KeyRepository) ListActiveForTerminal(
	ctx context.Context,
	terminalSerial string,
) ([]models.Key, error) {
	var terminalID int64
	var terminalIsActive int

	err := r.db.QueryRowContext(ctx, `
		SELECT id, is_active
		FROM terminals
		WHERE serial = ?
	`, terminalSerial).Scan(&terminalID, &terminalIsActive)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTerminalNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find terminal for keys: %w", err)
	}

	if terminalIsActive != 1 {
		return nil, ErrTerminalInactive
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
		    id,
		    name,
		    key_type,
		    key_value,
		    key_version,
		    terminal_id,
		    is_active,
		    created_by,
		    created_at,
		    updated_at
		FROM "keys"
		WHERE is_active = 1
		  AND (terminal_id IS NULL OR terminal_id = ?)
		ORDER BY key_type, name, key_version DESC
	`, terminalID)
	if err != nil {
		return nil, fmt.Errorf("list terminal keys: %w", err)
	}
	defer rows.Close()

	keys := make([]models.Key, 0)

	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate terminal keys: %w", err)
	}

	return keys, nil
}

type keyScanner interface {
	Scan(dest ...any) error
}

func scanKey(scanner keyScanner) (models.Key, error) {
	var key models.Key
	var terminalID sql.NullInt64
	var createdBy sql.NullInt64
	var isActive int

	err := scanner.Scan(
		&key.ID,
		&key.Name,
		&key.KeyType,
		&key.KeyValue,
		&key.KeyVersion,
		&terminalID,
		&isActive,
		&createdBy,
		&key.CreatedAt,
		&key.UpdatedAt,
	)

	if err != nil {
		return key, err
	}

	if terminalID.Valid {
		key.TerminalID = &terminalID.Int64
	}

	if createdBy.Valid {
		key.CreatedBy = &createdBy.Int64
	}

	key.IsActive = isActive == 1

	return key, nil
}

func int64PtrValue(value *int64) any {
	if value == nil {
		return nil
	}

	return *value
}
