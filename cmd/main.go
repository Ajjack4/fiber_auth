package main

import (
	"log"

	"github.com/Ajjack4/fiber_auth/config"
	"github.com/Ajjack4/fiber_auth/internal/handlers"
	"github.com/Ajjack4/fiber_auth/internal/middlewares"

	"github.com/gofiber/fiber/v2"
)

func main() {
	// Initialize the database
	if err := config.InitDB(); err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer config.DB.Close()

	// Initialize Fiber app
	app := fiber.New()

	// Routes
	app.Post("/login", handlers.LoginHandler)
	app.Post("/signup", handlers.SignupHandler)
	// app.Get("/protected", middlewares.AuthenticateJWT, handlers.ProtectedHandler)
	app.Put("/update", middlewares.AuthenticateJWT, handlers.UpdateHandler)
	app.Delete("/delete", middlewares.AuthenticateJWT, handlers.DeleteHandler)

	// Start the server
	log.Fatal(app.Listen(":3000"))
}
