package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"transport_api/internal/middleware"
	"transport_api/internal/models"
	"transport_api/internal/repositories"
)

type UserHandler struct {
	users *repositories.UserRepository
}

type userRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func NewUserHandler(users *repositories.UserRepository) *UserHandler {
	return &UserHandler{
		users: users,
	}
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	writeJSON(w, http.StatusOK, users)
}

func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	user, err := h.users.FindByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to find user")
		return
	}

	if user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeUserRequest(w, r)
	if !ok {
		return
	}

	user, ok := userFromRequest(w, request, true)
	if !ok {
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user.PasswordHash = string(hash)

	createdUser, err := h.users.Create(r.Context(), user)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "User with this username already exists")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, createdUser)
}

func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	request, ok := decodeUserRequest(w, r)
	if !ok {
		return
	}

	user, ok := userFromRequest(w, request, false)
	if !ok {
		return
	}

	if strings.TrimSpace(request.Password) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}

		user.PasswordHash = string(hash)
	}

	updatedUser, err := h.users.Update(r.Context(), id, user)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "User with this username already exists")
			return
		}

		writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}

	if updatedUser == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	writeJSON(w, http.StatusOK, updatedUser)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	claims, ok := middleware.CurrentUser(r.Context())
	if ok && claims.UserID == id {
		writeError(w, http.StatusBadRequest, "You cannot delete your own user")
		return
	}

	deleted, err := h.users.Delete(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func decodeUserRequest(w http.ResponseWriter, r *http.Request) (userRequest, bool) {
	var request userRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return request, false
	}

	return request, true
}

func userFromRequest(
	w http.ResponseWriter,
	request userRequest,
	isCreate bool,
) (models.User, bool) {
	username := strings.TrimSpace(request.Username)
	password := strings.TrimSpace(request.Password)
	role := strings.ToLower(strings.TrimSpace(request.Role))

	if username == "" {
		writeError(w, http.StatusBadRequest, "Username is required")
		return models.User{}, false
	}

	if isCreate && password == "" {
		writeError(w, http.StatusBadRequest, "Password is required")
		return models.User{}, false
	}

	if role == "" {
		role = "user"
	}

	if role != "admin" && role != "user" {
		writeError(w, http.StatusBadRequest, "Invalid role")
		return models.User{}, false
	}

	return models.User{
		Username: username,
		Role:     role,
	}, true
}
