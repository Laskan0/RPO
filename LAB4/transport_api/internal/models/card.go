package models

type Card struct {
	ID         int64   `json:"id"`
	CardNumber string  `json:"card_number"`
	OwnerName  *string `json:"owner_name,omitempty"`
	Balance    int64   `json:"balance"`
	IsBlocked  bool    `json:"is_blocked"`
	KeyID      *int64  `json:"key_id,omitempty"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}
