package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"transport_api/internal/middleware"
	"transport_api/internal/models"
	"transport_api/internal/repositories"
)

type KeyHandler struct {
	keys *repositories.KeyRepository
}

type keyRequest struct {
	Name       string `json:"name"`
	KeyType    string `json:"key_type"`
	KeyValue   string `json:"key_value"`
	KeyVersion *int   `json:"key_version"`
	TerminalID *int64 `json:"terminal_id"`
	IsActive   *bool  `json:"is_active"`
}

func NewKeyHandler(keys *repositories.KeyRepository) *KeyHandler {
	return &KeyHandler{
		keys: keys,
	}
}

func (h *KeyHandler) List(w http.ResponseWriter, r *http.Request) {
	keys, err := h.keys.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list keys")
		return
	}

	writeJSON(w, http.StatusOK, keys)
}

func (h *KeyHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	key, err := h.keys.FindByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find key")
		return
	}

	if key == nil {
		writeError(w, http.StatusNotFound, "Key not found")
		return
	}

	writeJSON(w, http.StatusOK, key)
}

func (h *KeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeKeyRequest(w, r)
	if !ok {
		return
	}

	key, ok := keyFromRequest(w, request, true)
	if !ok {
		return
	}

	claims, ok := middleware.CurrentUser(r.Context())
	if ok {
		key.CreatedBy = &claims.UserID
	}

	createdKey, err := h.keys.Create(r.Context(), key)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			writeError(w, http.StatusBadRequest, "Terminal not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to create key")
		return
	}

	writeJSON(w, http.StatusCreated, createdKey)
}

func (h *KeyHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	request, ok := decodeKeyRequest(w, r)
	if !ok {
		return
	}

	key, ok := keyFromRequest(w, request, false)
	if !ok {
		return
	}

	updatedKey, err := h.keys.Update(r.Context(), id, key)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			writeError(w, http.StatusBadRequest, "Terminal not found")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to update key")
		return
	}

	if updatedKey == nil {
		writeError(w, http.StatusNotFound, "Key not found")
		return
	}

	writeJSON(w, http.StatusOK, updatedKey)
}

func (h *KeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	deleted, err := h.keys.Delete(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "Key not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *KeyHandler) ListForTerminal(w http.ResponseWriter, r *http.Request) {
	terminalSerial := strings.TrimSpace(r.URL.Query().Get("terminal_serial"))

	if terminalSerial == "" {
		writeError(w, http.StatusBadRequest, "terminal_serial query parameter is required")
		return
	}

	keys, err := h.keys.ListActiveForTerminal(r.Context(), terminalSerial)
	if err != nil {
		if errors.Is(err, repositories.ErrTerminalNotFound) {
			writeError(w, http.StatusNotFound, "Terminal not found")
			return
		}

		if errors.Is(err, repositories.ErrTerminalInactive) {
			writeError(w, http.StatusForbidden, "Terminal is inactive")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to load terminal keys")
		return
	}

	writeJSON(w, http.StatusOK, keys)
}

func decodeKeyRequest(w http.ResponseWriter, r *http.Request) (keyRequest, bool) {
	var request keyRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return request, false
	}

	return request, true
}

func keyFromRequest(
	w http.ResponseWriter,
	request keyRequest,
	isCreate bool,
) (models.Key, bool) {
	name := strings.TrimSpace(request.Name)
	keyType := strings.ToLower(strings.TrimSpace(request.KeyType))
	keyValue := strings.TrimSpace(request.KeyValue)

	if name == "" {
		writeError(w, http.StatusBadRequest, "Name is required")
		return models.Key{}, false
	}

	if keyType == "" {
		keyType = "mifare"
	}

	if keyType != "mifare" && keyType != "terminal" && keyType != "system" {
		writeError(w, http.StatusBadRequest, "Invalid key_type")
		return models.Key{}, false
	}

	if keyValue == "" {
		writeError(w, http.StatusBadRequest, "Key value is required")
		return models.Key{}, false
	}

	keyVersion := 1

	if request.KeyVersion != nil {
		keyVersion = *request.KeyVersion
	}

	if keyVersion <= 0 {
		writeError(w, http.StatusBadRequest, "Key version must be greater than zero")
		return models.Key{}, false
	}

	if request.TerminalID != nil && *request.TerminalID <= 0 {
		writeError(w, http.StatusBadRequest, "terminal_id must be greater than zero")
		return models.Key{}, false
	}

	isActive := true

	if request.IsActive != nil {
		isActive = *request.IsActive
	} else if !isCreate {
		isActive = true
	}

	return models.Key{
		Name:       name,
		KeyType:    keyType,
		KeyValue:   keyValue,
		KeyVersion: keyVersion,
		TerminalID: request.TerminalID,
		IsActive:   isActive,
	}, true
}
