package handlers

import (
	"encoding/json"
	"net/http"

	"lab2/internal/auth"
	"lab2/internal/repository"
)

func DatabaseSummary(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		summary, err := store.Summary(r.Context())
		if err != nil {
			http.Error(w, "failed to load database summary", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"summary": summary,
		}

		// Returning JWT claims here makes it easy to verify that auth already works.
		if claims, ok := auth.GetClaims(r.Context()); ok {
			response["current_user"] = claims
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}
