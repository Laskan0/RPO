package handlers

import (
	"net/http"
	"os"
)

func SwaggerUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := os.ReadFile("docs/swagger.html")
		if err != nil {
			http.Error(w, "failed to load swagger page", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(content)
	}
}

func SwaggerSpec() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := os.ReadFile("docs/openapi.yaml")
		if err != nil {
			http.Error(w, "failed to load swagger spec", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Write(content)
	}
}
