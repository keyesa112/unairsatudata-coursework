package main

import (
	"project-crud/routes"
	"github.com/gofiber/fiber/v2"	
)

func main() {
	//Fiber instance
	app := fiber.New()

	//Routes
	routes.RouterApp(app)

	//Start Server
	app.Listen(":3000")
}