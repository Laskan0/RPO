package main

import (
	"log"

	"lab2/internal/app"
)

func main() {
	application, err := app.New()
	if err != nil {
		log.Fatalf("create app: %v", err)
	}

	if err := application.Run(); err != nil {
		log.Fatalf("run app: %v", err)
	}
}
