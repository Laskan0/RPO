package models

type Key struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	KeyType    string `json:"key_type"`
	KeyValue   string `json:"key_value"`
	KeyVersion int    `json:"key_version"`
	TerminalID *int64 `json:"terminal_id,omitempty"`
	IsActive   bool   `json:"is_active"`
	CreatedBy  *int64 `json:"created_by,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}
