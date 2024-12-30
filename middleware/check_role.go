package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"fmt"
)

// Middleware to check user role
func CheckRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Ambil token JWT dari header Authorization
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
		}

		// Menghapus kata "Bearer " jika ada
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Validasi token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Pastikan algoritma JWT adalah HS256
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(http.StatusUnauthorized, "Invalid signing method")
			}
			// Kembalikan secret key
			return []byte("y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"), nil
		})

		if err != nil {
			// Log error untuk debugging
			fmt.Println("Error parsing token:", err)
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or missing token"})
		}

		// Periksa apakah token valid
		if !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or missing token"})
		}

		// Ambil klaim dari token
		claims := token.Claims.(jwt.MapClaims)
		role, ok := claims["role"].(string)  // Pastikan kita mengambil klaim yang benar (role, bukan role_aktif)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Role not found in token"})
		}

		// Periksa apakah role sesuai
		if role != requiredRole {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Access denied"})
		}

		// Lanjutkan ke handler berikutnya
		return c.Next()
	}
}
