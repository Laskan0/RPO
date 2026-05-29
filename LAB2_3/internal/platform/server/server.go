package server

import (
	"context"
	"net/http"
)

// Server wraps http.Server so startup and shutdown logic stays in one place.
type Server struct {
	address string
	server  *http.Server
}

func New(address string, handler http.Handler) *Server {
	return &Server{
		address: address,
		server: &http.Server{
			Addr:    address,
			Handler: handler,
		},
	}
}

func (s *Server) Run() error {
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) Address() string {
	return s.address
}
