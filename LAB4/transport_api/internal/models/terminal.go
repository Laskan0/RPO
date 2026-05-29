package models

type Terminal struct {
	ID        int64   `json:"id"`
	Serial    string  `json:"serial"`
	Name      string  `json:"name"`
	Location  *string `json:"location,omitempty"`
	IsActive  bool    `json:"is_active"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}
