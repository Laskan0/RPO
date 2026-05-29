package handlers

import (
	"net/http"

	"transport_api/internal/repositories"
)

type TransactionHandler struct {
	transactions *repositories.TransactionRepository
}

func NewTransactionHandler(
	transactions *repositories.TransactionRepository,
) *TransactionHandler {
	return &TransactionHandler{
		transactions: transactions,
	}
}

func (h *TransactionHandler) List(w http.ResponseWriter, r *http.Request) {
	transactions, err := h.transactions.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list transactions")
		return
	}

	writeJSON(w, http.StatusOK, transactions)
}

func (h *TransactionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	transaction, err := h.transactions.FindByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find transaction")
		return
	}

	if transaction == nil {
		writeError(w, http.StatusNotFound, "Transaction not found")
		return
	}

	writeJSON(w, http.StatusOK, transaction)
}
