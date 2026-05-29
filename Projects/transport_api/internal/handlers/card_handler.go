package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"transport_api/internal/models"
	"transport_api/internal/repositories"
)

type CardHandler struct {
	cards *repositories.CardRepository
}

type cardRequest struct {
	CardNumber string `json:"card_number"`
	OwnerName  string `json:"owner_name"`
	Balance    *int64 `json:"balance"`
	IsBlocked  *bool  `json:"is_blocked"`
	KeyID      *int64 `json:"key_id"`
}

func NewCardHandler(cards *repositories.CardRepository) *CardHandler {
	return &CardHandler{
		cards: cards,
	}
}

func (h *CardHandler) List(w http.ResponseWriter, r *http.Request) {
	cards, err := h.cards.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list cards")
		return
	}

	writeJSON(w, http.StatusOK, cards)
}

func (h *CardHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	card, err := h.cards.FindByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find card")
		return
	}

	if card == nil {
		writeError(w, http.StatusNotFound, "Card not found")
		return
	}

	writeJSON(w, http.StatusOK, card)
}

func (h *CardHandler) Create(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeCardRequest(w, r)
	if !ok {
		return
	}

	card, ok := cardFromRequest(w, request, true)
	if !ok {
		return
	}

	createdCard, err := h.cards.Create(r.Context(), card)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "Card with this number already exists")
			return
		}

		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			writeError(w, http.StatusBadRequest, "Key not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to create card")
		return
	}

	writeJSON(w, http.StatusCreated, createdCard)
}

func (h *CardHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	request, ok := decodeCardRequest(w, r)
	if !ok {
		return
	}

	card, ok := cardFromRequest(w, request, false)
	if !ok {
		return
	}

	updatedCard, err := h.cards.Update(r.Context(), id, card)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "Card with this number already exists")
			return
		}

		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			writeError(w, http.StatusBadRequest, "Key not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to update card")
		return
	}

	if updatedCard == nil {
		writeError(w, http.StatusNotFound, "Card not found")
		return
	}

	writeJSON(w, http.StatusOK, updatedCard)
}

func (h *CardHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	deleted, err := h.cards.Delete(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete card")
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "Card not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func decodeCardRequest(w http.ResponseWriter, r *http.Request) (cardRequest, bool) {
	var request cardRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return request, false
	}

	return request, true
}

func cardFromRequest(
	w http.ResponseWriter,
	request cardRequest,
	isCreate bool,
) (models.Card, bool) {
	cardNumber := strings.ToLower(strings.TrimSpace(request.CardNumber))
	ownerNameText := strings.TrimSpace(request.OwnerName)

	if cardNumber == "" {
		writeError(w, http.StatusBadRequest, "Card number is required")
		return models.Card{}, false
	}

	balance := int64(0)

	if request.Balance != nil {
		balance = *request.Balance
	} else if !isCreate {
		writeError(w, http.StatusBadRequest, "Balance is required")
		return models.Card{}, false
	}

	if balance < 0 {
		writeError(w, http.StatusBadRequest, "Balance cannot be negative")
		return models.Card{}, false
	}

	if request.KeyID != nil && *request.KeyID <= 0 {
		writeError(w, http.StatusBadRequest, "Key ID must be positive")
		return models.Card{}, false
	}

	isBlocked := false

	if request.IsBlocked != nil {
		isBlocked = *request.IsBlocked
	}

	var ownerName *string
	if ownerNameText != "" {
		ownerName = &ownerNameText
	}

	return models.Card{
		CardNumber: cardNumber,
		OwnerName:  ownerName,
		Balance:    balance,
		IsBlocked:  isBlocked,
		KeyID:      request.KeyID,
	}, true
}
