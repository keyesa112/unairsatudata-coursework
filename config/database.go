package config

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DB is a global variable that will hold the MongoDB connection
var DB *mongo.Database

// ConnectDB initializes the MongoDB connection
func ConnectDB() {
	log.Println("Connecting to MongoDB...")

	// Set timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Replace <db_password> with your actual MongoDB Atlas password
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://talidah2022:2711un%40ir@cluster0.zcv8h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"))
	if err != nil {
		log.Fatal("Error connecting to MongoDB: ", err)
	}

	// Replace "unairastu" with your actual database name
	DB = client.Database("unairastu")
	log.Println("Connected to MongoDB!")
}

// GetCollection returns a MongoDB collection
func GetCollection(collectionName string) *mongo.Collection {
	// Ensure the DB connection is initialized
	if DB == nil {
		ConnectDB() // Connect to MongoDB if not connected yet
	}

	return DB.Collection(collectionName)
}
