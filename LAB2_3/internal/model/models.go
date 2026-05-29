package model

import "time"

type Key struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type Terminal struct {
	ID           int64     `json:"id"`
	SerialNumber string    `json:"serial_number"`
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}

type User struct {
	ID           int64     `json:"id"`
	Login        string    `json:"login"`
	FullName     string    `json:"full_name"`
	PasswordHash string    `json:"password_hash"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
}

type Card struct {
	ID         int64     `json:"id"`
	CardNumber string    `json:"card_number"`
	OwnerName  string    `json:"owner_name"`
	Balance    int64     `json:"balance"`
	IsBlocked  bool      `json:"is_blocked"`
	KeyID      int64     `json:"key_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type Transaction struct {
	ID         int64     `json:"id"`
	Amount     int64     `json:"amount"`
	CardID     int64     `json:"card_id"`
	TerminalID int64     `json:"terminal_id"`
	Authorized bool      `json:"authorized"`
	CreatedAt  time.Time `json:"created_at"`
}
