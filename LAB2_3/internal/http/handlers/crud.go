package handlers

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"lab2/internal/model"
	"lab2/internal/repository"
)

type keyRequest struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

type terminalRequest struct {
	SerialNumber string `json:"serial_number"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	IsActive     bool   `json:"is_active"`
}

type userRequest struct {
	Login    string `json:"login"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

type userResponse struct {
	ID        int64     `json:"id"`
	Login     string    `json:"login"`
	FullName  string    `json:"full_name"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

type cardRequest struct {
	CardNumber string `json:"card_number"`
	OwnerName  string `json:"owner_name"`
	Balance    int64  `json:"balance"`
	IsBlocked  bool   `json:"is_blocked"`
	KeyID      int64  `json:"key_id"`
}

type transactionRequest struct {
	Amount     int64 `json:"amount"`
	CardID     int64 `json:"card_id"`
	TerminalID int64 `json:"terminal_id"`
	Authorized bool  `json:"authorized"`
}

func KeysCollection(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := store.ListKeys(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load keys")
				return
			}

			writeJSON(w, http.StatusOK, items)
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}

			var request keyRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateKeyRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			id, err := store.CreateKey(r.Context(), model.Key{
				Name:        strings.TrimSpace(request.Name),
				Value:       strings.TrimSpace(request.Value),
				Description: strings.TrimSpace(request.Description),
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create key")
				return
			}

			item, err := store.GetKeyByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load created key")
				return
			}

			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func KeyItem(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.URL.Path, "/api/v1/keys/")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid key id")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := store.GetKeyByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "key not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load key")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			if !requireAdmin(w, r) {
				return
			}

			var request keyRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateKeyRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			if err := store.UpdateKey(r.Context(), model.Key{
				ID:          id,
				Name:        strings.TrimSpace(request.Name),
				Value:       strings.TrimSpace(request.Value),
				Description: strings.TrimSpace(request.Description),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update key")
				return
			}

			item, err := store.GetKeyByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated key")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			if !requireAdmin(w, r) {
				return
			}

			if err := store.DeleteKey(r.Context(), id); err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "key not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to delete key")
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func TerminalsCollection(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := store.ListTerminals(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load terminals")
				return
			}

			writeJSON(w, http.StatusOK, items)
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}

			var request terminalRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateTerminalRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			id, err := store.CreateTerminal(r.Context(), model.Terminal{
				SerialNumber: strings.TrimSpace(request.SerialNumber),
				Name:         strings.TrimSpace(request.Name),
				Address:      strings.TrimSpace(request.Address),
				IsActive:     request.IsActive,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create terminal")
				return
			}

			item, err := store.GetTerminalByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load created terminal")
				return
			}

			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func TerminalItem(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.URL.Path, "/api/v1/terminals/")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid terminal id")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := store.GetTerminalByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "terminal not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load terminal")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			if !requireAdmin(w, r) {
				return
			}

			var request terminalRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateTerminalRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			if err := store.UpdateTerminal(r.Context(), model.Terminal{
				ID:           id,
				SerialNumber: strings.TrimSpace(request.SerialNumber),
				Name:         strings.TrimSpace(request.Name),
				Address:      strings.TrimSpace(request.Address),
				IsActive:     request.IsActive,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update terminal")
				return
			}

			item, err := store.GetTerminalByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated terminal")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			if !requireAdmin(w, r) {
				return
			}

			if err := store.DeleteTerminal(r.Context(), id); err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "terminal not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to delete terminal")
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func UsersCollection(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := claimsFromRequest(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing auth claims")
			return
		}

		switch r.Method {
		case http.MethodGet:
			if !claims.IsAdmin {
				item, err := store.GetUserByID(r.Context(), claims.UserID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to load current user")
					return
				}

				writeJSON(w, http.StatusOK, []userResponse{toUserResponse(*item)})
				return
			}

			items, err := store.ListUsers(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load users")
				return
			}

			writeJSON(w, http.StatusOK, toUserResponses(items))
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}

			var request userRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if request.Password == "" {
				writeError(w, http.StatusBadRequest, "password is required")
				return
			}

			if err := validateUserRequest(request, true); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to hash password")
				return
			}

			id, err := store.CreateUser(r.Context(), model.User{
				Login:        strings.TrimSpace(request.Login),
				FullName:     strings.TrimSpace(request.FullName),
				PasswordHash: string(passwordHash),
				IsAdmin:      request.IsAdmin,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create user")
				return
			}

			item, err := store.GetUserByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load created user")
				return
			}

			writeJSON(w, http.StatusCreated, toUserResponse(*item))
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func UserItem(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := claimsFromRequest(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing auth claims")
			return
		}

		id, err := parseID(r.URL.Path, "/api/v1/users/")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		switch r.Method {
		case http.MethodGet:
			if !claims.IsAdmin && claims.UserID != id {
				writeError(w, http.StatusForbidden, "user can access only own profile")
				return
			}

			item, err := store.GetUserByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load user")
				return
			}

			writeJSON(w, http.StatusOK, toUserResponse(*item))
		case http.MethodPut:
			if !claims.IsAdmin && claims.UserID != id {
				writeError(w, http.StatusForbidden, "user can update only own profile")
				return
			}

			var request userRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateUserRequest(request, false); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			currentUser, err := store.GetUserByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load user")
				return
			}

			passwordHash := currentUser.PasswordHash
			if request.Password != "" {
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to hash password")
					return
				}

				passwordHash = string(hashedPassword)
			}

			if err := store.UpdateUser(r.Context(), model.User{
				ID:           id,
				Login:        strings.TrimSpace(request.Login),
				FullName:     strings.TrimSpace(request.FullName),
				PasswordHash: passwordHash,
				IsAdmin:      userAdminFlag(claims.IsAdmin, request.IsAdmin, currentUser.IsAdmin),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update user")
				return
			}

			item, err := store.GetUserByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated user")
				return
			}

			writeJSON(w, http.StatusOK, toUserResponse(*item))
		case http.MethodDelete:
			if !claims.IsAdmin {
				writeError(w, http.StatusForbidden, "only admin can delete users")
				return
			}

			if err := store.DeleteUser(r.Context(), id); err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "user not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to delete user")
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func CardsCollection(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := store.ListCards(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load cards")
				return
			}

			writeJSON(w, http.StatusOK, items)
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}

			var request cardRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateCardRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			id, err := store.CreateCard(r.Context(), model.Card{
				CardNumber: strings.TrimSpace(request.CardNumber),
				OwnerName:  strings.TrimSpace(request.OwnerName),
				Balance:    request.Balance,
				IsBlocked:  request.IsBlocked,
				KeyID:      request.KeyID,
			})
			if err != nil {
				if existing, lookupErr := store.GetCardByNumber(r.Context(), strings.TrimSpace(request.CardNumber)); lookupErr == nil && existing != nil {
					writeError(w, http.StatusConflict, "card already exists")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to create card")
				return
			}

			item, err := store.GetCardByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load created card")
				return
			}

			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func CardItem(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.URL.Path, "/api/v1/cards/")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid card id")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := store.GetCardByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "card not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load card")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			if !requireAdmin(w, r) {
				return
			}

			var request cardRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := validateCardRequest(request); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			if err := store.UpdateCard(r.Context(), model.Card{
				ID:         id,
				CardNumber: strings.TrimSpace(request.CardNumber),
				OwnerName:  strings.TrimSpace(request.OwnerName),
				Balance:    request.Balance,
				IsBlocked:  request.IsBlocked,
				KeyID:      request.KeyID,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update card")
				return
			}

			item, err := store.GetCardByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated card")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			if !requireAdmin(w, r) {
				return
			}

			if err := store.DeleteCard(r.Context(), id); err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "card not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to delete card")
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func TransactionsCollection(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := store.ListTransactions(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load transactions")
				return
			}

			writeJSON(w, http.StatusOK, items)
		case http.MethodPost:
			if !requireAdmin(w, r) {
				return
			}

			var request transactionRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			id, err := store.CreateTransaction(r.Context(), model.Transaction{
				Amount:     request.Amount,
				CardID:     request.CardID,
				TerminalID: request.TerminalID,
				Authorized: request.Authorized,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create transaction")
				return
			}

			item, err := store.GetTransactionByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load created transaction")
				return
			}

			writeJSON(w, http.StatusCreated, item)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func TransactionItem(store *repository.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.URL.Path, "/api/v1/transactions/")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid transaction id")
			return
		}

		switch r.Method {
		case http.MethodGet:
			item, err := store.GetTransactionByID(r.Context(), id)
			if err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "transaction not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to load transaction")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			if !requireAdmin(w, r) {
				return
			}

			var request transactionRequest
			if err := decodeJSON(r, &request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			if err := store.UpdateTransaction(r.Context(), model.Transaction{
				ID:         id,
				Amount:     request.Amount,
				CardID:     request.CardID,
				TerminalID: request.TerminalID,
				Authorized: request.Authorized,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update transaction")
				return
			}

			item, err := store.GetTransactionByID(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load updated transaction")
				return
			}

			writeJSON(w, http.StatusOK, item)
		case http.MethodDelete:
			if !requireAdmin(w, r) {
				return
			}

			if err := store.DeleteTransaction(r.Context(), id); err != nil {
				if isNotFound(err) {
					writeError(w, http.StatusNotFound, "transaction not found")
					return
				}

				writeError(w, http.StatusInternalServerError, "failed to delete transaction")
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func toUserResponses(items []model.User) []userResponse {
	result := make([]userResponse, 0, len(items))
	for _, item := range items {
		result = append(result, toUserResponse(item))
	}

	return result
}

func toUserResponse(item model.User) userResponse {
	return userResponse{
		ID:        item.ID,
		Login:     item.Login,
		FullName:  item.FullName,
		IsAdmin:   item.IsAdmin,
		CreatedAt: item.CreatedAt,
	}
}

func userAdminFlag(currentUserIsAdmin bool, requestedIsAdmin bool, existingIsAdmin bool) bool {
	if currentUserIsAdmin {
		return requestedIsAdmin
	}

	return existingIsAdmin
}

func validateKeyRequest(request keyRequest) error {
	if strings.TrimSpace(request.Name) == "" {
		return errValidation("key name is required")
	}
	if strings.TrimSpace(request.Value) == "" {
		return errValidation("key value is required")
	}
	return nil
}

func validateTerminalRequest(request terminalRequest) error {
	if strings.TrimSpace(request.SerialNumber) == "" {
		return errValidation("terminal serial number is required")
	}
	if strings.TrimSpace(request.Name) == "" {
		return errValidation("terminal name is required")
	}
	if strings.TrimSpace(request.Address) == "" {
		return errValidation("terminal address is required")
	}
	return nil
}

func validateUserRequest(request userRequest, passwordRequired bool) error {
	if strings.TrimSpace(request.Login) == "" {
		return errValidation("user login is required")
	}
	if strings.TrimSpace(request.FullName) == "" {
		return errValidation("user full name is required")
	}
	if passwordRequired && strings.TrimSpace(request.Password) == "" {
		return errValidation("password is required")
	}
	if strings.TrimSpace(request.Password) != "" && len(strings.TrimSpace(request.Password)) < 4 {
		return errValidation("password must contain at least 4 characters")
	}
	return nil
}

func validateCardRequest(request cardRequest) error {
	if strings.TrimSpace(request.CardNumber) == "" {
		return errValidation("card number is required")
	}
	if strings.TrimSpace(request.OwnerName) == "" {
		return errValidation("card owner name is required")
	}
	if request.Balance < 0 {
		return errValidation("card balance cannot be negative")
	}
	if request.KeyID <= 0 {
		return errValidation("valid key id is required")
	}
	return nil
}

func errValidation(message string) error {
	return &validationError{message: message}
}

type validationError struct {
	message string
}

func (e *validationError) Error() string {
	return e.message
}
