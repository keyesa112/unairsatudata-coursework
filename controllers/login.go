package controllers

import (
	"context"
	"fmt"
	"project-crud/models"
	"project-crud/utils"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

// Secret key untuk menandatangani JWT
const secretKey = "y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"

// Fungsi Login
func Login(c *fiber.Ctx) error {
	// Membuat konteks
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Membuat variabel untuk menyimpan data login
	var loginData models.Login

	// Parsing body request ke struct loginData
	if err := c.BodyParser(&loginData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Mencari user di database
	user := models.Users{}
	err := userCollection.FindOne(ctx, bson.M{"username": loginData.Username}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found!"})
	}

	// Mencocokkan password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(loginData.Pass)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid password!"})
	}

	// Menentukan role berdasarkan ID role aktif
	roleID := user.Role_aktif.Hex() // Mengambil ID role aktif
	roleName := ""

	// Menentukan role berdasarkan ID
	if roleID == "673d5456289e27e2597765cd" {
		roleName = "admin"
	} else if roleID == "673d54c7289e27e2597765ce" {
		roleName = "civitas"
	} else {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid role"})
	}

	// Menentukan jenis user berdasarkan id_jenis_user menggunakan if-else
	jenisUser := ""
	if user.Id_jenis_user.Hex() == "673d5e1207846022c2110a79" {
		jenisUser = "Mahasiswa"
	} else if user.Id_jenis_user.Hex() == "673d5e7d07846022c2110a7a" {
		jenisUser = "Dosen"
	} else if user.Id_jenis_user.Hex() == "673d5e8107846022c2110a7b" {
		jenisUser = "Tendik"
	} else if user.Id_jenis_user.Hex() == "673d5e8507846022c2110a7c" {
		jenisUser = "KPS"
	} else if user.Id_jenis_user.Hex() == "673d5e8e07846022c2110a7d" {
		jenisUser = "Dekanat"
	} else if user.Id_jenis_user.Hex() == "673d5e9307846022c2110a7e" {
		jenisUser = "Ketua_Unit"
	} else if user.Id_jenis_user.Hex() == "673d5e9e07846022c2110a7f" {
		jenisUser = "Pimpinan_Univ"
	} else {
		jenisUser = "Unknown" // Default jika tidak ditemukan jenis user
	}

	// Membuat token JWT
	token, err := utils.GenerateJWT(user.Username, roleName, jenisUser, secretKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not login!"})
	}

	// Print the generated token to the console
	fmt.Println("Generated JWT Token:", token)

	// Mengembalikan token, role, id_jenis_user, jenis user, user_id, dan username
	return c.JSON(fiber.Map{
		"token":        token,
		"role":         roleName,        // Menambahkan role ke response
		"jenis_user":   jenisUser,       // Menambahkan jenis user ke response
		"user_id":      user.ID.Hex(),
		"username":     user.Username,
		"id_jenis_user": user.Id_jenis_user.Hex(),  // Menambahkan id_jenis_user ke response
	})
	
}
