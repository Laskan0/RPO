package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"transport_api/internal/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (r *UserRepository) List(ctx context.Context) ([]models.User, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, password_hash, role, created_at, updated_at
		FROM users
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]models.User, 0)

	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	return users, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id int64) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, created_at, updated_at
		FROM users
		WHERE id = ?
	`, id)

	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, created_at, updated_at
		FROM users
		WHERE username = ?
	`, username)

	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("find user by username: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user models.User) (*models.User, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES (?, ?, ?)
	`,
		user.Username,
		user.PasswordHash,
		user.Role,
	)

	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get user id: %w", err)
	}

	return r.FindByID(ctx, id)
}

func (r *UserRepository) Update(ctx context.Context, id int64, user models.User) (*models.User, error) {
	var result sql.Result
	var err error

	if user.PasswordHash == "" {
		result, err = r.db.ExecContext(ctx, `
			UPDATE users
			SET username = ?,
			    role = ?,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`,
			user.Username,
			user.Role,
			id,
		)
	} else {
		result, err = r.db.ExecContext(ctx, `
			UPDATE users
			SET username = ?,
			    password_hash = ?,
			    role = ?,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`,
			user.Username,
			user.PasswordHash,
			user.Role,
			id,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
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

func (r *UserRepository) Delete(ctx context.Context, id int64) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM users
		WHERE id = ?
	`, id)

	if err != nil {
		return false, fmt.Errorf("delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner userScanner) (models.User, error) {
	var user models.User

	err := scanner.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return user, err
	}

	return user, nil
}
