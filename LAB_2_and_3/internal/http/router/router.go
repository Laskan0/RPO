package router

import (
	"net/http"

	"lab2/internal/auth"
	"lab2/internal/http/handlers"
	"lab2/internal/repository"
)

func New(store *repository.Store, authService *auth.Service) http.Handler {
	mux := http.NewServeMux()

	// All API routes are grouped under /api/v1 to match the lab requirements.
	mux.HandleFunc("/api/v1/health", handlers.Health)
	mux.HandleFunc("/api/v1/login", handlers.Login(authService))
	mux.HandleFunc("/api/v1/swagger", handlers.SwaggerUI())
	mux.HandleFunc("/api/v1/swagger/", handlers.SwaggerSpec())

	protected := authService.AuthMiddleware
	mux.Handle("/api/v1/debug/db", protected(handlers.DatabaseSummary(store)))
	mux.Handle("/api/v1/keys", protected(handlers.KeysCollection(store)))
	mux.Handle("/api/v1/keys/", protected(handlers.KeyItem(store)))
	mux.Handle("/api/v1/terminals", protected(handlers.TerminalsCollection(store)))
	mux.Handle("/api/v1/terminals/", protected(handlers.TerminalItem(store)))
	mux.Handle("/api/v1/users", protected(handlers.UsersCollection(store)))
	mux.Handle("/api/v1/users/", protected(handlers.UserItem(store)))
	mux.Handle("/api/v1/cards", protected(handlers.CardsCollection(store)))
	mux.Handle("/api/v1/cards/", protected(handlers.CardItem(store)))
	mux.Handle("/api/v1/transactions", protected(handlers.TransactionsCollection(store)))
	mux.Handle("/api/v1/transactions/", protected(handlers.TransactionItem(store)))
	mux.HandleFunc("/api/v1/terminal/authorize", handlers.TerminalAuthorizePayment(store))
	mux.HandleFunc("/api/v1/terminal/keys", handlers.TerminalLoadKeys(store))

	return mux
}
