package controllers

import (
	"context"
	"project-crud/config"
	"project-crud/models"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Fungsi untuk mengambil profil pengguna berdasarkan username
func GetProfile(c *fiber.Ctx) error {
	// Mengambil token dari header Authorization
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token is required"})
	}

	// Menghapus kata "Bearer" jika ada, untuk mendapatkan token murni
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Memverifikasi token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Memastikan token menggunakan metode signing yang benar
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte("y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"), nil
	})

	// Mengecek error dan validitas token
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token", "details": err.Error()})
	}

	// Mengambil claims dari token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Could not parse token claims"})
	}

	// Mengambil username dari claims
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is missing from token"})
	}

	// Membuat context untuk query ke database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mencari user berdasarkan username
	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Memastikan ada modul_ids yang terkait dengan pengguna
	if len(user.ModulIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "User does not have associated modules"})
	}

	// Mengambil modul-modul yang terkait dengan user
	modulCollection := config.GetCollection("modul")
	cursor, err := modulCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.ModulIDs}})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	// Menyimpan hasil modul-modul ke dalam array modulResults
	var modulResults []models.Modul
	if err := cursor.All(ctx, &modulResults); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Menyusun response dengan data user dan modul-modulnya
	userProfile := struct {
		ID       string       `json:"id"`
		Username string       `json:"username"`
		Email    string       `json:"email"`
		Modules  []models.Modul `json:"modules"`
	}{
		ID:       user.ID.Hex(),
		Username: user.Username,
		Email:    user.Email,
		Modules:  modulResults,
	}

	// Mengembalikan data profil user
	return c.Status(fiber.StatusOK).JSON(userProfile)
}
