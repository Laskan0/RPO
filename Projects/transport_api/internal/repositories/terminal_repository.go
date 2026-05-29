package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"transport_api/internal/models"
)

type TerminalRepository struct {
	db *sql.DB
}

func NewTerminalRepository(db *sql.DB) *TerminalRepository {
	return &TerminalRepository{
		db: db,
	}
}

func (r *TerminalRepository) List(ctx context.Context) ([]models.Terminal, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, serial, name, location, is_active, created_at, updated_at
		FROM terminals
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list terminals: %w", err)
	}
	defer rows.Close()

	terminals := make([]models.Terminal, 0)

	for rows.Next() {
		terminal, err := scanTerminal(rows)
		if err != nil {
			return nil, err
		}

		terminals = append(terminals, terminal)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate terminals: %w", err)
	}

	return terminals, nil
}

func (r *TerminalRepository) FindByID(ctx context.Context, id int64) (*models.Terminal, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, serial, name, location, is_active, created_at, updated_at
		FROM terminals
		WHERE id = ?
	`, id)

	terminal, err := scanTerminal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &terminal, nil
}

func (r *TerminalRepository) FindBySerial(ctx context.Context, serial string) (*models.Terminal, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, serial, name, location, is_active, created_at, updated_at
		FROM terminals
		WHERE serial = ?
	`, serial)

	terminal, err := scanTerminal(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &terminal, nil
}

func (r *TerminalRepository) Create(ctx context.Context, terminal models.Terminal) (*models.Terminal, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO terminals (serial, name, location, is_active)
		VALUES (?, ?, ?, ?)
	`,
		terminal.Serial,
		terminal.Name,
		locationValue(terminal.Location),
		boolToInt(terminal.IsActive),
	)

	if err != nil {
		return nil, fmt.Errorf("create terminal: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get terminal id: %w", err)
	}

	return r.FindByID(ctx, id)
}

func (r *TerminalRepository) Update(ctx context.Context, id int64, terminal models.Terminal) (*models.Terminal, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE terminals
		SET serial = ?,
		    name = ?,
		    location = ?,
		    is_active = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`,
		terminal.Serial,
		terminal.Name,
		locationValue(terminal.Location),
		boolToInt(terminal.IsActive),
		id,
	)

	if err != nil {
		return nil, fmt.Errorf("update terminal: %w", err)
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

func (r *TerminalRepository) Delete(ctx context.Context, id int64) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM terminals
		WHERE id = ?
	`, id)

	if err != nil {
		return false, fmt.Errorf("delete terminal: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

type terminalScanner interface {
	Scan(dest ...any) error
}

func scanTerminal(scanner terminalScanner) (models.Terminal, error) {
	var terminal models.Terminal
	var location sql.NullString
	var isActive int

	err := scanner.Scan(
		&terminal.ID,
		&terminal.Serial,
		&terminal.Name,
		&location,
		&isActive,
		&terminal.CreatedAt,
		&terminal.UpdatedAt,
	)

	if err != nil {
		return terminal, err
	}

	if location.Valid {
		terminal.Location = &location.String
	}

	terminal.IsActive = isActive == 1

	return terminal, nil
}

func locationValue(location *string) any {
	if location == nil {
		return nil
	}

	return *location
}

func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}
