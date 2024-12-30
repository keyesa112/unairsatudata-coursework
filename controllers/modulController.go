package controllers

import (
	"context"
	"project-crud/config"
	"project-crud/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var modulCollection *mongo.Collection

func init() {
	// Initialize the modulCollection (Assuming you've set up a MongoDB connection)
	modulCollection = config.GetCollection("modul")
}

// Create a new Modul
// Fungsi untuk membuat modul baru
func CreateModul(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var modul models.Modul
    if err := c.BodyParser(&modul); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }

    // Membuat modul baru
    newModul := models.Modul{
        ID:         primitive.NewObjectID(),
        Nm_modul:   modul.Nm_modul,
        Ket_modul:  modul.Ket_modul,
        Kategori_id: modul.Kategori_id,
        Is_aktif:   modul.Is_aktif,
        Alamat:     modul.Alamat,
        Urutan:     modul.Urutan,
        Gbr_icon:   modul.Gbr_icon,
        Created_at: primitive.NewDateTimeFromTime(time.Now()),
        Created_by: modul.Created_by,
        Updated_at: primitive.NewDateTimeFromTime(time.Now()),
        Updated_by: modul.Updated_by,
        Icon:       modul.Icon,
    }

    // Memasukkan modul baru ke koleksi
    _, err := modulCollection.InsertOne(ctx, newModul)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(fiber.StatusCreated).JSON(newModul)
}


// Get all Modul
// Fungsi untuk mendapatkan semua modul
func GetModuls(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var moduls []models.Modul
    cursor, err := modulCollection.Find(ctx, bson.M{})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    for cursor.Next(ctx) {
        var modul models.Modul
        if err := cursor.Decode(&modul); err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
        }
        moduls = append(moduls, modul)
    }

    return c.Status(fiber.StatusOK).JSON(moduls)
}

// Get Modul by ID
// Fungsi untuk mendapatkan modul berdasarkan ID
func GetModulByID(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    id := c.Params("id")
    objID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid module ID"})
    }

    var modul models.Modul
    err = modulCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&modul)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Module not found"})
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(fiber.StatusOK).JSON(modul)
}

// Update Modul by ID
// Fungsi untuk memperbarui modul berdasarkan ID
func UpdateModulByID(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    id := c.Params("id")
    objID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid module ID"})
    }

    var modul models.Modul
    if err := c.BodyParser(&modul); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
    }

    // Update data modul
    _, err = modulCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": modul})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(fiber.StatusOK).JSON(modul)
}


// Delete Modul by ID
// Fungsi untuk menghapus modul berdasarkan ID
func DeleteModulByID(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    id := c.Params("id")
    objID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid module ID"})
    }

    // Hapus modul berdasarkan ID
    _, err = modulCollection.DeleteOne(ctx, bson.M{"_id": objID})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Module deleted successfully"})
}

