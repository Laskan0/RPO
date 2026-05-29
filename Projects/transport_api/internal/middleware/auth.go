package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"transport_api/internal/services"
)

type contextKey string

const claimsContextKey contextKey = "jwt_claims"

type errorResponse struct {
	Error string `json:"error"`
}

func AuthRequired(jwtService *services.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			if authHeader == "" {
				writeError(w, http.StatusUnauthorized, "Missing Authorization header")
				return
			}

			const prefix = "Bearer "

			if !strings.HasPrefix(authHeader, prefix) {
				writeError(w, http.StatusUnauthorized, "Invalid Authorization header")
				return
			}

			tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))

			if tokenString == "" {
				writeError(w, http.StatusUnauthorized, "Missing token")
				return
			}

			claims, err := jwtService.Parse(tokenString)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AdminRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := CurrentUser(r.Context())

		if !ok {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if claims.Role != "admin" {
			writeError(w, http.StatusForbidden, "Admin access required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CurrentUser(ctx context.Context) (*services.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*services.Claims)
	return claims, ok
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(errorResponse{
		Error: message,
	})
}
