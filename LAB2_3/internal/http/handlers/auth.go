package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"lab2/internal/auth"
)

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string            `json:"token"`
	User  loginUserResponse `json:"user"`
}

type loginUserResponse struct {
	ID       int64  `json:"id"`
	Login    string `json:"login"`
	FullName string `json:"full_name"`
	IsAdmin  bool   `json:"is_admin"`
}

func Login(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request loginRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		token, user, err := authService.Login(r.Context(), request.Login, request.Password)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				http.Error(w, "invalid login or password", http.StatusUnauthorized)
				return
			}

			http.Error(w, "failed to login", http.StatusInternalServerError)
			return
		}

		response := loginResponse{
			Token: token,
			User: loginUserResponse{
				ID:       user.ID,
				Login:    user.Login,
				FullName: user.FullName,
				IsAdmin:  user.IsAdmin,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}
