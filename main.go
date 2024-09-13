package main

import (
	Models "Bmessage_backend/models"
	"Bmessage_backend/routs/auth"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("ошибка загрузки .env файла: %v", err)
	}

	Models.MigrationUsertabel()

	router := gin.Default()
	auth.AuthRouter(router)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/swagger-docs")))
	router.GET("/swagger-docs", func(c *gin.Context) {
		c.File("./docs/swagger.json")
	})
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
	})

	serverPort := os.Getenv("SERVER_PORT")
	log.Println("сервер запущен, порт:", serverPort)
	router.Run(":" + serverPort)
}
