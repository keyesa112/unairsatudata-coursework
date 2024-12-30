package routes

import (
	"project-crud/controllers"
	"project-crud/middleware"
	"github.com/gofiber/fiber/v2"
)

func RouterApp(app *fiber.App) {
	// Grup API untuk endpoint yang dimulai dengan /api
	api := app.Group("/api")

	// Login route available for all users
	api.Post("/login", controllers.Login) 

	// Route untuk mengambil profil user berdasarkan user_id, masukkan ke dalam grup api
	api.Get("/profile", controllers.GetProfile) 

	// Terapkan JWTMiddleware ke seluruh API kecuali login
	api.Use(middleware.JWTMiddleware()) 

	// Admin Group
	adminGroup := api.Group("/admin", middleware.CheckRole("admin"))
	{
		// User-related routes
		adminGroup.Post("/create-users", controllers.CreateUser)
		adminGroup.Get("/get-users", controllers.GetUsers)
		adminGroup.Get("/get-users/:id", controllers.GetUserByID)
		adminGroup.Put("/update-users/:id", controllers.UpdateUserByID)
		adminGroup.Delete("/delete-users/:id", controllers.DeleteUser)
		adminGroup.Post("/:id/upload-image", controllers.UploadImage)
		adminGroup.Put("/:id/change-password", controllers.ChangePassword) //sama `aja kaya update by id
		adminGroup.Get("/users/:id/modules", controllers.GetUserModules)
		adminGroup.Put("/:id/change-jenisuser", controllers.UpdateUserJenisUser)
		adminGroup.Put("/:id/add-modul", controllers.AddModulToUser)
		adminGroup.Delete("/:id/remove-modul", controllers.RemoveModulFromUser)


		// Role-related routes
		adminGroup.Get("/roles", controllers.GetRoles)
		adminGroup.Post("/roles", controllers.CreateRole)
		adminGroup.Put("/roles/:id", controllers.UpdateRole) 
		adminGroup.Delete("/roles/:id", controllers.DeleteRole)

		// Jenis User-related routes
		adminGroup.Get("/jenisuser", controllers.GetJenisUsers)
		adminGroup.Post("/jenisuser", controllers.CreateJenisUser)
		adminGroup.Put("/jenisuser/:id", controllers.UpdateJenisUser)
		adminGroup.Delete("/jenisuser/:id", controllers.DeleteJenisUser)
		adminGroup.Put("/jenisuser/:id/add-modul", controllers.AddModulToJenisUser) //sama aja kaya update
		adminGroup.Put("/jenisuser/:id/remove-modul", controllers.RemoveModulFromJenisUser)

		// Modul-related routes
		adminGroup.Get("/modul", controllers.GetModuls)
		adminGroup.Post("/modul", controllers.CreateModul)
		adminGroup.Put("/modul/:id", controllers.UpdateModulByID)
		adminGroup.Delete("/modul/:id", controllers.DeleteModulByID)
	}

	// Civitas Group
	civitasGroup := api.Group("/civitas", middleware.CheckRole("civitas"))
	{
		// Login, Upload Photo, and Change Password
		civitasGroup.Post("/upload-image", controllers.UploadImageCivitas)
		civitasGroup.Put("/change-password", controllers.ChangePasswordCivitas)
	}
}
