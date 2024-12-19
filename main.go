package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = "supersecretkey"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"` 
}

var mockUser = User{
	ID:       1,
	Username: "testuser",
	Password: "password123",
}

func main() {
	app := fiber.New()

	app.Post("/login", loginHandler)
	app.Get("/protected", authenticateJWT, protectedHandler)

	app.Listen(":3000")
}

func loginHandler(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	if req.Username != mockUser.Username || req.Password != mockUser.Password {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": mockUser.ID,
		"exp":     time.Now().Add(time.Minute * 1).Unix(),
	})
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not generate token",
		})
	}

	return c.JSON(fiber.Map{
		"token": signedToken,
	})
}

func authenticateJWT(c *fiber.Ctx) error {
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing or invalid token",
		})
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	c.Locals("user", token.Claims.(jwt.MapClaims))
	return c.Next()
}

func protectedHandler(c *fiber.Ctx) error {
	user := c.Locals("user").(jwt.MapClaims)
	return c.JSON(fiber.Map{
		"message": "Welcome to the protected route!",
		"user":    user,
	})
}
