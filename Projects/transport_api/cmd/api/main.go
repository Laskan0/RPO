package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"transport_api/internal/config"
	"transport_api/internal/db"
	"transport_api/internal/handlers"
	appmiddleware "transport_api/internal/middleware"
	"transport_api/internal/repositories"
	"transport_api/internal/services"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer database.Close()

	if err := db.RunMigrations(database, "./migrations"); err != nil {
		log.Fatalf("migration error: %v", err)
	}

	adminCreated, err := db.SeedAdmin(database)
	if err != nil {
		log.Fatalf("seed error: %v", err)
	}

	if err := db.SeedDemoData(database); err != nil {
		log.Fatal(err)
	}

	if adminCreated {
		log.Println("seeded admin user: username=admin password=admin123")
		log.Println("change ADMIN_PASSWORD later before final submission")
	}

	userRepository := repositories.NewUserRepository(database)
	terminalRepository := repositories.NewTerminalRepository(database)
	cardRepository := repositories.NewCardRepository(database)
	paymentRepository := repositories.NewPaymentRepository(database)
	transactionRepository := repositories.NewTransactionRepository(database)
	keyRepository := repositories.NewKeyRepository(database)

	jwtService := services.NewJWTService(cfg.JWTSecret)

	authHandler := handlers.NewAuthHandler(userRepository, jwtService)
	userHandler := handlers.NewUserHandler(userRepository)
	terminalHandler := handlers.NewTerminalHandler(terminalRepository)
	cardHandler := handlers.NewCardHandler(cardRepository)
	terminalPaymentHandler := handlers.NewTerminalPaymentHandler(paymentRepository)
	transactionHandler := handlers.NewTransactionHandler(transactionRepository)
	keyHandler := handlers.NewKeyHandler(keyRepository)

	router := chi.NewRouter()

	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.RealIP)
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)

	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"status":  "ok",
				"service": "transport_api",
			})
		})

		r.Get("/swagger", handlers.SwaggerPage)
		r.Get("/swagger/", handlers.SwaggerPage)

		r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/yaml")
			http.ServeFile(w, r, "./docs/openapi.yaml")
		})

		r.Post("/auth/login", authHandler.Login)

		r.Group(func(protected chi.Router) {
			protected.Use(appmiddleware.AuthRequired(jwtService))

			protected.Get("/auth/me", authHandler.Me)

			protected.Get("/users", userHandler.List)
			protected.Get("/users/{id}", userHandler.Get)
			protected.With(appmiddleware.AdminRequired).Post("/users", userHandler.Create)
			protected.With(appmiddleware.AdminRequired).Put("/users/{id}", userHandler.Update)
			protected.With(appmiddleware.AdminRequired).Delete("/users/{id}", userHandler.Delete)

			protected.Get("/terminals", terminalHandler.List)
			protected.Get("/terminals/{id}", terminalHandler.Get)
			protected.With(appmiddleware.AdminRequired).Post("/terminals", terminalHandler.Create)
			protected.With(appmiddleware.AdminRequired).Put("/terminals/{id}", terminalHandler.Update)
			protected.With(appmiddleware.AdminRequired).Delete("/terminals/{id}", terminalHandler.Delete)

			protected.Get("/cards", cardHandler.List)
			protected.Get("/cards/{id}", cardHandler.Get)
			protected.With(appmiddleware.AdminRequired).Post("/cards", cardHandler.Create)
			protected.With(appmiddleware.AdminRequired).Put("/cards/{id}", cardHandler.Update)
			protected.With(appmiddleware.AdminRequired).Delete("/cards/{id}", cardHandler.Delete)

			protected.Get("/transactions", transactionHandler.List)
			protected.Get("/transactions/{id}", transactionHandler.Get)

			protected.Get("/keys", keyHandler.List)
			protected.Get("/keys/{id}", keyHandler.Get)
			protected.With(appmiddleware.AdminRequired).Post("/keys", keyHandler.Create)
			protected.With(appmiddleware.AdminRequired).Put("/keys/{id}", keyHandler.Update)
			protected.With(appmiddleware.AdminRequired).Delete("/keys/{id}", keyHandler.Delete)

			protected.Post(
				"/terminal/transactions/authorize",
				terminalPaymentHandler.Authorize,
			)

			protected.Get("/terminal/keys", keyHandler.ListForTerminal)
		})
	})

	log.Printf("transport_api listening on %s", cfg.Addr)

	if err := http.ListenAndServe(cfg.Addr, router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json error: %v", err)
	}
}
