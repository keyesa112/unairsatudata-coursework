package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

// Middleware to check user type
func CheckJenisUser(requiredJenisUser string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Ambil token JWT dari header Authorization
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Token not provided"})
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

		if err != nil || !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or missing token"})
		}

		// Ambil klaim dari token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unable to extract claims"})
		}

		// Periksa apakah klaim jenis_user ada dan cocok
		jenisUser, ok := claims["jenis_user"].(string)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "User type not found in token"})
		}

		// Periksa apakah jenis user sesuai
		if jenisUser != requiredJenisUser {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Access denied"})
		}

		// Lanjutkan ke handler berikutnya
		return c.Next()
	}
}
