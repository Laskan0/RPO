package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"lab2/internal/auth"
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func parseID(path string, prefix string) (int64, error) {
	idPart := strings.TrimPrefix(path, prefix)
	idPart = strings.Trim(idPart, "/")
	if idPart == "" {
		return 0, errors.New("missing id")
	}

	return strconv.ParseInt(idPart, 10, 64)
}

func claimsFromRequest(r *http.Request) (*auth.Claims, bool) {
	return auth.GetClaims(r.Context())
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims, ok := claimsFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing auth claims")
		return false
	}

	if !claims.IsAdmin {
		writeError(w, http.StatusForbidden, "only admin can change data")
		return false
	}

	return true
}

func isNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
