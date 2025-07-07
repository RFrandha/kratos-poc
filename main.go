package main

import (
	"log"
	"ory-kratos-poc/app"
)

func main() {
	application, err := app.New()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Start the server.
	application.Start(":8080")
}
