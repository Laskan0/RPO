package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"transport_api/internal/middleware"
	"transport_api/internal/models"
	"transport_api/internal/repositories"
	"transport_api/internal/services"
)

type AuthHandler struct {
	users *repositories.UserRepository
	jwt   *services.JWTService
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string      `json:"token"`
	User  userSummary `json:"user"`
}

type userSummary struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func NewAuthHandler(
	users *repositories.UserRepository,
	jwt *services.JWTService,
) *AuthHandler {
	return &AuthHandler{
		users: users,
		jwt:   jwt,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	if request.Username == "" || request.Password == "" {
		writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	user, err := h.users.FindByUsername(r.Context(), request.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find user")
		return
	}

	if user == nil {
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	if !passwordMatches(user, request.Password) {
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	token, err := h.jwt.Generate(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		Token: token,
		User: userSummary{
			ID:       user.ID,
			Username: user.Username,
			Role:     user.Role,
		},
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.CurrentUser(r.Context())

	if !ok {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	writeJSON(w, http.StatusOK, userSummary{
		ID:       claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
	})
}

func passwordMatches(user *models.User, password string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	)

	return err == nil
}
