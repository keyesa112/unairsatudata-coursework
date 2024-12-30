package controllers

import (
	"context"
	"project-crud/config"
	"project-crud/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	// "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive" // Import untuk bekerja dengan ObjectID
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Fungsi untuk mendapatkan semua role
func GetRoles(c *fiber.Ctx) error {
	collection := config.DB.Collection("roles")
	var roles []models.Role
	cursor, err := collection.Find(context.Background(), bson.D{}, options.Find())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error fetching roles",
			"error":   err.Error(),
		})
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var role models.Role
		if err := cursor.Decode(&role); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error decoding role",
				"error":   err.Error(),
			})
		}
		roles = append(roles, role)
	}

	if err := cursor.Err(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Cursor error",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(roles)
}

// Fungsi untuk membuat role baru
func CreateRole(c *fiber.Ctx) error {
	var role models.Role
	if err := c.BodyParser(&role); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
			"error":   err.Error(),
		})
	}

	// Pastikan Anda mengatur Created_at dan Updated_at
	role.Created_at = primitive.NewDateTimeFromTime(time.Now())
	role.Updated_at = primitive.NewDateTimeFromTime(time.Now())

	collection := config.DB.Collection("roles")
	_, err := collection.InsertOne(context.Background(), role)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error inserting role",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(role)
}

// Fungsi untuk mengupdate role
func UpdateRole(c *fiber.Ctx) error {
	// Mengambil roleID dari params dan mengonversinya menjadi ObjectID
	roleID := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid Object ID format",
			"error":   err.Error(),
		})
	}

	var role models.Role
	if err := c.BodyParser(&role); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
			"error":   err.Error(),
		})
	}

	collection := config.DB.Collection("roles")
	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		bson.M{"$set": bson.M{"name": role.Nm_role}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error updating role",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Role updated successfully",
	})
}

// Fungsi untuk menghapus role
func DeleteRole(c *fiber.Ctx) error {
	// Mengambil roleID dari params dan mengonversinya menjadi ObjectID
	roleID := c.Params("id")
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid Object ID format",
			"error":   err.Error(),
		})
	}

	collection := config.DB.Collection("roles")
	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error deleting role",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Role deleted successfully",
	})
}
