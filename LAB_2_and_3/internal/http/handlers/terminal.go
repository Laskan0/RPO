package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"lab2/internal/repository"
)

type terminalPaymentRequest struct {
	TerminalSerialNumber string `json:"terminal_serial_number"`
	CardNumber           string `json:"card_number"`
	Amount               int64  `json:"amount"`
}

type terminalPaymentResponse struct {
	Authorized  bool   `json:"authorized"`
	Message     string `json:"message"`
	Transaction any    `json:"transaction"`
}

func TerminalAuthorizePayment(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var request terminalPaymentRequest
		if err := decodeJSON(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if request.Amount <= 0 {
			writeError(w, http.StatusBadRequest, "amount must be greater than zero")
			return
		}

		transaction, message, err := store.AuthorizePayment(r.Context(), request.TerminalSerialNumber, request.CardNumber, request.Amount)
		if err != nil {
			switch {
			case errors.Is(err, sql.ErrNoRows):
				writeError(w, http.StatusNotFound, "card or terminal not found")
			case errors.Is(err, repository.ErrTerminalInactive):
				writeError(w, http.StatusForbidden, "terminal is inactive")
			default:
				writeError(w, http.StatusInternalServerError, "failed to authorize payment")
			}

			return
		}

		writeJSON(w, http.StatusOK, terminalPaymentResponse{
			Authorized:  transaction.Authorized,
			Message:     message,
			Transaction: transaction,
		})
	}
}

func TerminalLoadKeys(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		serialNumber := r.URL.Query().Get("terminal_serial_number")
		if serialNumber == "" {
			writeError(w, http.StatusBadRequest, "terminal_serial_number is required")
			return
		}

		terminal, err := store.GetTerminalBySerialNumber(r.Context(), serialNumber)
		if err != nil {
			if isNotFound(err) {
				writeError(w, http.StatusNotFound, "terminal not found")
				return
			}

			writeError(w, http.StatusInternalServerError, "failed to load terminal")
			return
		}

		if !terminal.IsActive {
			writeError(w, http.StatusForbidden, "terminal is inactive")
			return
		}

		keys, err := store.ListKeys(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load keys")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"terminal": terminal,
			"keys":     keys,
		})
	}
}
