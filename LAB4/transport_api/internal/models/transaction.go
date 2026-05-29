package models

type Transaction struct {
	ID             int64  `json:"id"`
	TerminalID     int64  `json:"terminal_id"`
	CardID         int64  `json:"card_id"`
	TerminalSerial string `json:"terminal_serial"`
	CardNumber     string `json:"card_number"`
	Amount         int64  `json:"amount"`
	Status         string `json:"status"`
	BalanceBefore  *int64 `json:"balance_before,omitempty"`
	BalanceAfter   *int64 `json:"balance_after,omitempty"`
	Message        string `json:"message"`
	CreatedAt      string `json:"created_at"`
}
