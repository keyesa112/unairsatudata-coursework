package middleware

import (
	"project-crud/utils"
	"github.com/gofiber/fiber/v2"
	"strings"
	"fmt"
)

// JWTMiddleware is a middleware to validate JWT
func JWTMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the token from the request header
		token := c.Get("Authorization")

		// Debugging: Log the token received
		fmt.Println("Received token:", token)

		// Check if the token is provided
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
		}

		// Remove "Bearer " prefix if it's present
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		} else {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token format"})
		}

		// Validate the token
		username, err := utils.ValidateJWT(token, "y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB") // Use the same secret key
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}

		// Set username in context for the next handlers
		c.Locals("username", username)

		// Proceed to the next handler
		return c.Next()
	}
}
