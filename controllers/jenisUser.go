package controllers

import (
	"context"
	"fmt"
	"project-crud/config"
	"project-crud/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive" // Import untuk bekerja dengan ObjectID
)

// Fungsi untuk mendapatkan semua jenis user
func GetJenisUsers(c *fiber.Ctx) error {
	collection := config.DB.Collection("jenis_users")
	var jenisUsers []models.JenisUser

	cursor, err := collection.Find(context.Background(), bson.D{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error fetching JenisUsers",
			"error":   err.Error(),
		})
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var jenisUser models.JenisUser
		if err := cursor.Decode(&jenisUser); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error decoding JenisUser",
				"error":   err.Error(),
			})
		}
		jenisUsers = append(jenisUsers, jenisUser)
	}

	if err := cursor.Err(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Cursor error",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(jenisUsers)
}

// Fungsi untuk membuat jenis user baru
func CreateJenisUser(c *fiber.Ctx) error {
	var jenisUser models.JenisUser
	if err := c.BodyParser(&jenisUser); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
			"error":   err.Error(),
		})
	}

	// Pastikan modul_ids sudah ada dalam request, jika tidak kosongkan array
	if jenisUser.ModulIDs == nil {
		jenisUser.ModulIDs = []primitive.ObjectID{}
	}

	collection := config.DB.Collection("jenis_users")
	_, err := collection.InsertOne(context.Background(), jenisUser)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error inserting jenisUser",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(jenisUser)
}

// Fungsi untuk mengupdate jenis user
func UpdateJenisUser(c *fiber.Ctx) error {
	// Mengambil id dari params dan mengonversinya menjadi ObjectID
	id := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid Object ID format",
			"error":   err.Error(),
		})
	}

	var jenisUser models.JenisUser
	if err := c.BodyParser(&jenisUser); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
			"error":   err.Error(),
		})
	}

	// Update data jenis user, termasuk array modul_ids
	collection := config.DB.Collection("jenis_users")
	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		bson.M{"$set": bson.M{
			"nm_jenis_user": jenisUser.NmJenisUser,
			"modul_ids":     jenisUser.ModulIDs,
			"updated_at":    primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error updating jenisUser",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "JenisUser updated successfully",
	})
}

// Fungsi untuk menghapus jenis user
func DeleteJenisUser(c *fiber.Ctx) error {
	// Mengambil id dari params dan mengonversinya menjadi ObjectID
	id := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid Object ID format",
			"error":   err.Error(),
		})
	}

	collection := config.DB.Collection("jenis_users")
	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error deleting jenisUser",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "JenisUser deleted successfully",
	})
}

func AddModulToJenisUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mengambil ID jenis user dari parameter URL dan validasi formatnya
	id := c.Params("id")
	jenisUserID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid jenisUser ID format",
			"error":   err.Error(),
		})
	}

	// Mengambil array modul_ids dari request body
	var request struct {
		ModulIDs []string `json:"modul_ids"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request body format",
			"error":   err.Error(),
		})
	}

	// Validasi dan konversi modul_ids ke array ObjectID
	modulIDs := make([]primitive.ObjectID, 0, len(request.ModulIDs))
	for _, id := range request.ModulIDs {
		modulID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": fmt.Sprintf("Invalid modul ID format: %s", id),
				"error":   err.Error(),
			})
		}
		modulIDs = append(modulIDs, modulID)
	}

	// Update modul_ids pada collection `jenis_users`
	jenisUserCollection := config.DB.Collection("jenis_users")
	jenisUserUpdateResult, err := jenisUserCollection.UpdateOne(
		ctx,
		bson.M{"_id": jenisUserID},
		bson.M{"$addToSet": bson.M{"modul_ids": bson.M{"$each": modulIDs}}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to add modules to jenisUser",
			"error":   err.Error(),
		})
	}

	// Periksa apakah ada jenis_user yang diperbarui
	if jenisUserUpdateResult.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "JenisUser not found",
		})
	}

	// Update modul_ids pada collection `users` berdasarkan jenis_user_id
	userCollection := config.DB.Collection("users")
	userUpdateResult, err := userCollection.UpdateMany(
		ctx,
		bson.M{"id_jenis_user": jenisUserID},
		bson.M{"$addToSet": bson.M{"modul_ids": bson.M{"$each": modulIDs}}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to propagate module changes to users",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Modules added to jenisUser and propagated to users successfully",
		"jenis_user_updated": jenisUserUpdateResult.ModifiedCount,
		"users_updated":      userUpdateResult.ModifiedCount,
	})
}

// Fungsi untuk menghapus modul dari jenis user
func RemoveModulFromJenisUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Mengambil ID jenis user dari parameter URL dan validasi formatnya
	id := c.Params("id")
	jenisUserID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid jenisUser ID format",
			"error":   err.Error(),
		})
	}

	// Mengambil array modul_ids dari request body
	var request struct {
		ModulIDs []string `json:"modul_ids"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request body format",
			"error":   err.Error(),
		})
	}

	// Validasi dan konversi modul_ids ke array ObjectID
	modulIDs := make([]primitive.ObjectID, 0, len(request.ModulIDs))
	for _, id := range request.ModulIDs {
		modulID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": fmt.Sprintf("Invalid modul ID format: %s", id),
				"error":   err.Error(),
			})
		}
		modulIDs = append(modulIDs, modulID)
	}

	// Menghapus modul dari jenis_users
	jenisUserCollection := config.DB.Collection("jenis_users")
	jenisUserUpdateResult, err := jenisUserCollection.UpdateOne(
		ctx,
		bson.M{"_id": jenisUserID},
		bson.M{"$pull": bson.M{"modul_ids": bson.M{"$in": modulIDs}}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to remove modules from jenisUser",
			"error":   err.Error(),
		})
	}

	// Periksa apakah jenis_user ditemukan
	if jenisUserUpdateResult.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "JenisUser not found",
		})
	}

	// Menghapus modul dari pengguna yang memiliki jenis_user yang sama
	userCollection := config.DB.Collection("users")
	userUpdateResult, err := userCollection.UpdateMany(
		ctx,
		bson.M{"id_jenis_user": jenisUserID},
		bson.M{"$pull": bson.M{"modul_ids": bson.M{"$in": modulIDs}}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to propagate module removal to users",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Modules removed from jenisUser and propagated to users successfully",
		"jenis_user_updated": jenisUserUpdateResult.ModifiedCount,
		"users_updated":      userUpdateResult.ModifiedCount,
	})
}
