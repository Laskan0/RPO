package app

import (
	"context"
	"fmt"

	"lab2/internal/auth"
	"lab2/internal/config"
	httprouter "lab2/internal/http/router"
	"lab2/internal/platform/database"
	"lab2/internal/platform/server"
	"lab2/internal/repository"
)

type App struct {
	auth       *auth.Service
	db         *database.SQLiteDB
	store      *repository.Store
	httpServer *server.Server
}

func New() (*App, error) {
	cfg := config.Load()
	db, err := database.NewSQLite(cfg.DatabasePath)
	if err != nil {
		return nil, err
	}

	store := repository.NewStore(db.DB)
	authService := auth.NewService(store, cfg.JWTSecret)
	router := httprouter.New(store, authService)
	httpServer := server.New(cfg.HTTPAddress(), router)

	return &App{
		auth:       authService,
		db:         db,
		store:      store,
		httpServer: httpServer,
	}, nil
}

func (a *App) Run() error {
	fmt.Printf("server is starting on %s\n", a.httpServer.Address())

	return a.httpServer.Run()
}

func (a *App) Shutdown(ctx context.Context) error {
	if err := a.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	if a.db != nil {
		if err := a.db.Close(); err != nil {
			return err
		}
	}

	return nil
}
