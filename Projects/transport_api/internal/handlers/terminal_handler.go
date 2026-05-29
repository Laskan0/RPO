package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"transport_api/internal/models"
	"transport_api/internal/repositories"
)

type TerminalHandler struct {
	terminals *repositories.TerminalRepository
}

type terminalRequest struct {
	Serial   string `json:"serial"`
	Name     string `json:"name"`
	Location string `json:"location"`
	IsActive *bool  `json:"is_active"`
}

func NewTerminalHandler(terminals *repositories.TerminalRepository) *TerminalHandler {
	return &TerminalHandler{
		terminals: terminals,
	}
}

func (h *TerminalHandler) List(w http.ResponseWriter, r *http.Request) {
	terminals, err := h.terminals.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list terminals")
		return
	}

	writeJSON(w, http.StatusOK, terminals)
}

func (h *TerminalHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	terminal, err := h.terminals.FindByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find terminal")
		return
	}

	if terminal == nil {
		writeError(w, http.StatusNotFound, "Terminal not found")
		return
	}

	writeJSON(w, http.StatusOK, terminal)
}

func (h *TerminalHandler) Create(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeTerminalRequest(w, r)
	if !ok {
		return
	}

	terminal, ok := terminalFromRequest(w, request, true)
	if !ok {
		return
	}

	createdTerminal, err := h.terminals.Create(r.Context(), terminal)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "Terminal with this serial already exists")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to create terminal")
		return
	}

	writeJSON(w, http.StatusCreated, createdTerminal)
}

func (h *TerminalHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	request, ok := decodeTerminalRequest(w, r)
	if !ok {
		return
	}

	terminal, ok := terminalFromRequest(w, request, false)
	if !ok {
		return
	}

	updatedTerminal, err := h.terminals.Update(r.Context(), id, terminal)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "Terminal with this serial already exists")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to update terminal")
		return
	}

	if updatedTerminal == nil {
		writeError(w, http.StatusNotFound, "Terminal not found")
		return
	}

	writeJSON(w, http.StatusOK, updatedTerminal)
}

func (h *TerminalHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	deleted, err := h.terminals.Delete(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete terminal")
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "Terminal not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func parseIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	rawID := chi.URLParam(r, "id")

	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "Invalid id")
		return 0, false
	}

	return id, true
}

func decodeTerminalRequest(w http.ResponseWriter, r *http.Request) (terminalRequest, bool) {
	var request terminalRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return request, false
	}

	return request, true
}

func terminalFromRequest(
	w http.ResponseWriter,
	request terminalRequest,
	isCreate bool,
) (models.Terminal, bool) {
	serial := strings.TrimSpace(request.Serial)
	name := strings.TrimSpace(request.Name)
	locationText := strings.TrimSpace(request.Location)

	if serial == "" {
		writeError(w, http.StatusBadRequest, "Serial is required")
		return models.Terminal{}, false
	}

	if name == "" {
		writeError(w, http.StatusBadRequest, "Name is required")
		return models.Terminal{}, false
	}

	isActive := true

	if request.IsActive != nil {
		isActive = *request.IsActive
	} else if !isCreate {
		isActive = true
	}

	var location *string
	if locationText != "" {
		location = &locationText
	}

	return models.Terminal{
		Serial:   serial,
		Name:     name,
		Location: location,
		IsActive: isActive,
	}, true
}
