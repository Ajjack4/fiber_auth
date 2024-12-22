package handlers

import (
	"time"

	"github.com/Ajjack4/fiber_auth/config"
	"github.com/Ajjack4/fiber_auth/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = "supersecretkey"

// SignupHandler handles user registration
func SignupHandler(c *fiber.Ctx) error {
	var req models.User
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username and password are required"})
	}

	query := "INSERT INTO users (username, password) VALUES (?, ?)"
	result, err := config.DB.Exec(query, req.Username, req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save user", "details": err.Error()})
	}

	insertID, err := result.LastInsertId()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get insert ID"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": insertID,
		"exp":     time.Now().Add(time.Minute * 30).Unix(),
	})
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	return c.JSON(fiber.Map{"token": signedToken})
}

// LoginHandler handles user login
func LoginHandler(c *fiber.Ctx) error {
	// Logic for user login
}
