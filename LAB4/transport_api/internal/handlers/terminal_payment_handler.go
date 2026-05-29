package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"transport_api/internal/repositories"
)

type TerminalPaymentHandler struct {
	payments *repositories.PaymentRepository
}

type authorizePaymentRequest struct {
	TerminalSerial string `json:"terminal_serial"`
	CardNumber     string `json:"card_number"`
	Amount         int64  `json:"amount"`
}

func NewTerminalPaymentHandler(
	payments *repositories.PaymentRepository,
) *TerminalPaymentHandler {
	return &TerminalPaymentHandler{
		payments: payments,
	}
}

func (h *TerminalPaymentHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	var request authorizePaymentRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	request.TerminalSerial = strings.TrimSpace(request.TerminalSerial)
	request.CardNumber = strings.ToLower(strings.TrimSpace(request.CardNumber))

	if request.TerminalSerial == "" {
		writeError(w, http.StatusBadRequest, "Terminal serial is required")
		return
	}

	if request.CardNumber == "" {
		writeError(w, http.StatusBadRequest, "Card number is required")
		return
	}

	if request.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "Amount must be greater than zero")
		return
	}

	result, err := h.payments.AuthorizePayment(
		r.Context(),
		repositories.PaymentAuthorizationInput{
			TerminalSerial: request.TerminalSerial,
			CardNumber:     request.CardNumber,
			Amount:         request.Amount,
		},
	)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to authorize payment")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
