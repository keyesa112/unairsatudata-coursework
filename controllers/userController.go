package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	"project-crud/config"
	"project-crud/models"
)

// Mendapatkan koleksi MongoDB untuk "users" dan "jenis_users"
var userCollection *mongo.Collection = config.GetCollection("users")
var jenisUserCollection *mongo.Collection = config.GetCollection("jenis_users")

// Fungsi untuk membuat user baru
func CreateUser(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var user models.Users
    if err := c.BodyParser(&user); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }

    // Cek apakah username sudah ada
    var existingUser models.Users
    err := userCollection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&existingUser)
    if err == nil {
        // Jika username sudah ditemukan
        return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
    }
    if err != mongo.ErrNoDocuments {
        // Error selain 'no documents'
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    // Cek apakah Id_jenis_user valid
    var jenisUser models.JenisUser
    err = jenisUserCollection.FindOne(ctx, bson.M{"_id": user.Id_jenis_user}).Decode(&jenisUser)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Id_jenis_user"})
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    // Ambil modul berdasarkan Id_jenis_user
    modulIDs := jenisUser.ModulIDs

    // Hashing password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Pass), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
    }

    // Membuat user baru
    newUser := models.Users{
        ID:           primitive.NewObjectID(),
        Username:     user.Username,
        Nm_user:      user.Nm_user,
        Pass:         string(hashedPassword),
        Email:        user.Email,
        Role_aktif:   user.Role_aktif,
        Jenis_kelamin: user.Jenis_kelamin,
        Photo:        user.Photo,
        Phone:        user.Phone,
        Id_jenis_user: user.Id_jenis_user,
        ModulIDs:      modulIDs, // Menambahkan modul yang terkait
    }

    // Memasukkan user baru ke koleksi
    _, err = userCollection.InsertOne(ctx, newUser)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(fiber.StatusCreated).JSON(newUser)
}


// Fungsi untuk mendapatkan semua user
func GetUsers(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var users []models.Users
	cursor, err := userCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	for cursor.Next(ctx) {
		var user models.Users
		if err := cursor.Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		users = append(users, user)
	}

	return c.Status(fiber.StatusOK).JSON(users)
}

// GetUserByID retrieves a user by ID
func GetUserByID(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

// UpdateUserByID updates a user by ID
func UpdateUserByID(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var user models.Users
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": user})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

func DeleteUser(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Ambil ID user dari parameter URL
    userID := c.Params("id")

    // Validasi apakah ID user adalah ObjectID yang valid
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
    }

    // Hapus user dari database
    result, err := userCollection.DeleteOne(ctx, bson.M{"_id": objID})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete user"})
    }

    // Periksa apakah user ditemukan dan dihapus
    if result.DeletedCount == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "User deleted successfully"})
}

// Fungsi untuk mengubah password user
func ChangePassword(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Mendapatkan ID user dari parameter URL
    id := c.Params("id")
    objID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
    }

    // Struktur untuk input password lama dan baru
    type PasswordUpdate struct {
        OldPassword string `json:"old_password"`
        NewPassword string `json:"new_password"`
    }

    var passwordUpdate PasswordUpdate
    if err := c.BodyParser(&passwordUpdate); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }

    // Mendapatkan user dari database berdasarkan ID
    var user models.Users
    err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    // Verifikasi password lama
    err = bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(passwordUpdate.OldPassword))
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Old password is incorrect"})
    }

    // Hash password baru
    hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(passwordUpdate.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash new password"})
    }

    // Update field Pass dengan password baru yang sudah di-hash
    update := bson.M{"$set": bson.M{"pass": string(hashedNewPassword)}}
    _, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password"})
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Password updated successfully"})
}

// Fungsi untuk upload image dan update field photo pada dokumen user
func UploadImage(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mendapatkan ID user dari parameter URL
	id := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	// Mengambil file dari request
	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to get image file"})
	}

	// Membuat nama file baru dengan format YYYYMMDDHHmmSSsss.[file extension]
	currentTime := time.Now()
	fileExt := filepath.Ext(file.Filename)
	newFileName := fmt.Sprintf("%s%s", currentTime.Format("20060102150405.000"), fileExt)

	// Path penyimpanan file
	savePath := fmt.Sprintf("./storage/images/%s", newFileName)

	// Membuat direktori jika belum ada
	if _, err := os.Stat("./storage/images"); os.IsNotExist(err) {
		if err := os.MkdirAll("./storage/images", os.ModePerm); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create directory"})
		}
	}

	// Menyimpan file image
	if err := c.SaveFile(file, savePath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save image"})
	}

	// Update field photo pada dokumen user
	update := bson.M{"$set": bson.M{"photo": newFileName}}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user photo"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Image uploaded successfully", "fileName": newFileName})
}

// GetUserModules retrieves modules associated with a user by their ID
func GetUserModules(c *fiber.Ctx) error {
	// Membuat context dengan timeout 10 detik
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mendapatkan ID dari URL
	id := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		// Mengembalikan error jika ID tidak valid
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	// Mencari pengguna berdasarkan ID
	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Mengembalikan error jika pengguna tidak ditemukan
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		// Mengembalikan error jika terjadi kesalahan pada database
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Pastikan ada modul_ids dalam data user
	if len(user.ModulIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "User does not have associated modules"})
	}

	// Menggunakan aggregation untuk mengambil data modul berdasarkan modul_ids
	modulCollection := config.GetCollection("modul")
	cursor, err := modulCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.ModulIDs}})
	if err != nil {
		// Mengembalikan error jika gagal menjalankan query
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx) // Pastikan cursor ditutup setelah selesai

	// Menyimpan hasil query modul ke dalam array modulResults
	var modulResults []models.Modul
	if err := cursor.All(ctx, &modulResults); err != nil {
		// Mengembalikan error jika gagal membaca hasil cursor
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Mengembalikan hasil modul yang ditemukan
	return c.Status(fiber.StatusOK).JSON(modulResults)
}

// UpdateUserJenisUser mengubah jenis user dan modul terkait
func UpdateUserJenisUser(c *fiber.Ctx) error {
	// Konteks dengan timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Koneksi ke database
	userCollection := config.GetCollection("users")
	jenisUserCollection := config.GetCollection("jenis_users")

	// Ambil ID User dari parameter dan ID JenisUser dari body
	userIDParam := c.Params("id") // Ambil ID dari parameter URL
	var reqBody struct {
		IdJenisUser string `json:"id_jenis_user"`
	}

	if err := c.BodyParser(&reqBody); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Log untuk debug
	fmt.Println("User ID Param:", userIDParam)
	fmt.Println("Request Body ID JenisUser:", reqBody.IdJenisUser)

	// Konversi ID ke ObjectID
	userID, err := primitive.ObjectIDFromHex(userIDParam)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	idJenisUser, err := primitive.ObjectIDFromHex(reqBody.IdJenisUser)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid jenis user ID format",
		})
	}

	// Cek apakah user ada
	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	} else if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Ambil data jenis user berdasarkan IdJenisUser
	var jenisUser models.JenisUser
	err = jenisUserCollection.FindOne(ctx, bson.M{"_id": idJenisUser}).Decode(&jenisUser)
	if err == mongo.ErrNoDocuments {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Jenis user not found",
		})
	} else if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Log untuk debugging
	fmt.Println("JenisUser Data:", jenisUser)

	// Update data user (Id_jenis_user dan ModulIDs)
	update := bson.M{
		"$set": bson.M{
			"id_jenis_user": idJenisUser,
			"modul_ids":     jenisUser.ModulIDs,
		},
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	// Log untuk debugging
	fmt.Println("Update berhasil")

	// Berikan respon sukses
	return c.JSON(fiber.Map{
		"message": "User updated successfully",
	})
}

func AddModulToUser(c *fiber.Ctx) error {
	// Konteks dengan timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Koneksi ke database
	userCollection := config.GetCollection("users")
	modulCollection := config.GetCollection("modul")

	// Ambil ID User dari parameter dan ID Modul dari body
	userIDParam := c.Params("id")
	var reqBody struct {
		ModulID string `json:"modul_ids"`
	}

	// Parse body request
	if err := c.BodyParser(&reqBody); err != nil {
		log.Printf("Error parsing request body: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Debug: Log nilai modul_id yang diterima
	log.Printf("Received modul_id from request body: %s", reqBody.ModulID)

	// Validasi panjang dan format ObjectID
	if len(reqBody.ModulID) != 24 || !isValidHex(reqBody.ModulID) {
		log.Printf("Invalid modul_id format: %s", reqBody.ModulID)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid modul ID format",
		})
	}

	// Validasi konversi userID
	if len(userIDParam) != 24 || !isValidHex(userIDParam) {
		log.Printf("Invalid user ID format: %s", userIDParam)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Konversi ID ke ObjectID
	modulID, err := primitive.ObjectIDFromHex(reqBody.ModulID)
	if err != nil {
		log.Printf("Error converting modul_id to ObjectID: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid modul ID",
		})
	}

	userID, err := primitive.ObjectIDFromHex(userIDParam)
	if err != nil {
		log.Printf("Error converting userID to ObjectID: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Periksa apakah modul tersebut ada di database
	err = modulCollection.FindOne(ctx, bson.M{"_id": modulID}).Decode(&models.Modul{})
	if err == mongo.ErrNoDocuments {
		log.Printf("Modul not found in database for ID: %v", modulID)
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Modul not found",
		})
	} else if err != nil {
		log.Printf("Database error: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Update data user dengan menambahkan modul ke daftar modul yang bisa diakses
	update := bson.M{
		"$addToSet": bson.M{
			"modul_ids": modulID,
		},
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		log.Printf("Failed to add modul to user: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to add modul",
		})
	}

	log.Printf("Modul added to user successfully")
	return c.JSON(fiber.Map{
		"message": "Modul added to user successfully",
	})
}

// Utility untuk validasi format hex
func isValidHex(id string) bool {
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func RemoveModulFromUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userCollection := config.GetCollection("users")

	userIDParam := c.Params("id")
	var reqBody struct {
		ModulID string `json:"modul_ids"`
	}

	// Log awal untuk melihat apakah body berhasil diparse
	log.Printf("Attempting to parse request body")
	if err := c.BodyParser(&reqBody); err != nil {
		log.Printf("Error parsing body: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Log data setelah parsing untuk memeriksa apakah body memiliki data yang benar
	log.Printf("Parsed request body: %+v", reqBody)

	// Validasi panjang ID
	if len(reqBody.ModulID) == 0 {
		log.Printf("Modul ID is empty, invalid request")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Modul ID cannot be empty",
		})
	}

	if len(reqBody.ModulID) != 24 {
		log.Printf("Modul ID invalid due to incorrect length: %d", len(reqBody.ModulID))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid modul ID format",
		})
	}

	// Validasi karakter jika perlu
	for _, r := range reqBody.ModulID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			log.Printf("Invalid character found in modul_id: %c", r)
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid modul ID characters",
			})
		}
	}

	// Validasi modul ID dengan MongoDB
	modulID, err := primitive.ObjectIDFromHex(reqBody.ModulID)
	if err != nil {
		log.Printf("Failed to convert modul_id to ObjectID: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid modul ID",
		})
	}

	// Validasi userID
	if len(userIDParam) != 24 {
		log.Printf("UserID is invalid due to incorrect length")
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	userID, err := primitive.ObjectIDFromHex(userIDParam)
	if err != nil {
		log.Printf("Failed to convert user ID to ObjectID: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Proses Update ke database
	update := bson.M{
		"$pull": bson.M{
			"modul_ids": modulID,
		},
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		log.Printf("Database update failed: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to remove modul",
		})
	}

	log.Printf("Modul successfully removed from user")
	return c.JSON(fiber.Map{
		"message": "Modul removed successfully",
	})
}

func UploadImageCivitas(c *fiber.Ctx) error {
	// Mengambil token dari header Authorization
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token is required"})
	}

	// Menghapus kata "Bearer" jika ada
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Memverifikasi token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Pastikan token menggunakan metode signing yang benar
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte("y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"), nil
	})

	// Mengecek validitas token
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token", "details": err.Error()})
	}

	// Mengambil claims dari token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Could not parse token claims"})
	}

	// Mengambil username dari claims
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is missing from token"})
	}

	// Mengambil file dari request
	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to get image file"})
	}

	// Membuat nama file baru dengan format YYYYMMDDHHmmSSsss.[file extension]
	currentTime := time.Now()
	fileExt := filepath.Ext(file.Filename)
	newFileName := fmt.Sprintf("%s%s", currentTime.Format("20060102150405.000"), fileExt)

	// Path penyimpanan file
	savePath := fmt.Sprintf("./storage/images/%s", newFileName)

	// Membuat direktori jika belum ada
	if _, err := os.Stat("./storage/images"); os.IsNotExist(err) {
		if err := os.MkdirAll("./storage/images", os.ModePerm); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create directory"})
		}
	}

	// Menyimpan file image
	if err := c.SaveFile(file, savePath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save image"})
	}

	// Update field photo pada dokumen user berdasarkan username
	userCollection := config.GetCollection("users")
	update := bson.M{"$set": bson.M{"photo": newFileName}}
	_, err = userCollection.UpdateOne(context.Background(), bson.M{"username": username}, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user photo"})
	}

	// Mengembalikan respons sukses
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "Image uploaded successfully",
		"fileName": newFileName,
	})
}

func ChangePasswordCivitas(c *fiber.Ctx) error {
	// Mengambil token dari header Authorization
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token is required"})
	}

	// Menghapus kata "Bearer" jika ada
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Memverifikasi token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Pastikan token menggunakan metode signing yang benar
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte("y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"), nil
	})

	// Mengecek validitas token
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token", "details": err.Error()})
	}

	// Mengambil claims dari token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Could not parse token claims"})
	}

	// Mengambil username dari claims
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username is missing from token"})
	}

	// Struktur untuk input password lama dan baru
	type PasswordUpdate struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	var passwordUpdate PasswordUpdate
	if err := c.BodyParser(&passwordUpdate); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Membuat context untuk query database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mendapatkan user dari database berdasarkan username
	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Verifikasi password lama
	err = bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(passwordUpdate.OldPassword))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Old password is incorrect"})
	}

	// Hash password baru
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(passwordUpdate.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash new password"})
	}

	// Update field Pass dengan password baru yang sudah di-hash
	update := bson.M{"$set": bson.M{"pass": string(hashedNewPassword)}}
	_, err = userCollection.UpdateOne(ctx, bson.M{"username": username}, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Password updated successfully"})
}




