package auth

import (
	"Bmessage_backend/database"
	"Bmessage_backend/helpers"
	"Bmessage_backend/models"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var jwtSecretKey = []byte(os.Getenv("ACCESS_SECRET"))

type TokenPayload struct {
	GUID string `json:"guid"`
	IP   string `json:"ip"`
	jwt.StandardClaims
}

func AuthRouter(router *gin.Engine) {
	roustBase := "auth/"
	router.GET(roustBase+"get-tokens", database.WithDatabase(GetTokens))
	router.GET(roustBase+"refresh-tokens", database.WithDatabase(RefreshTokens))
}

type GUIDTokens struct {
	GUID string `json:"GUID"`
}

// GetTokens генерирует токены для пользователя
// @Summary Получение токенов по GUID пользователя
// @Description Эндпойнт для генерации access и refresh токенов на основе GUID пользователя.
// @Tags Auth
// @Accept json
// @Produce json
// @Param GUID query string true "GUID пользователя"
// @Success 200 {object} map[string]interface{} "successful response"
// @Failure 400 {object} map[string]interface{} "bad request"
// @Failure 500 {object} map[string]interface{} "internal server error"
// @Router /auth/get-tokens [get]
func GetTokens(db *gorm.DB, c *gin.Context) {
	var requestData GUIDTokens

	requestData.GUID = c.Query("GUID")
	if requestData.GUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GUID is required"})
		return
	}

	clientIP := c.ClientIP()

	var user models.User
	if err := db.Where("guid = ?", requestData.GUID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			user = models.User{
				GUID:      requestData.GUID,
				Email:     "mock@example.com",
				RefreshIP: clientIP,
			}
			if err := db.Create(&user).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать пользователя"})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
			return
		}
	}

	accessToken, refreshToken, err := helpers.GenerateTokens(&user, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать токены"})
		return
	}

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось хэшировать refresh токен"})
		return
	}

	user.RefreshToken = string(hashedRefreshToken)
	user.RefreshIP = clientIP
	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": base64.StdEncoding.EncodeToString([]byte(refreshToken)),
	})
}

// RefreshTokens обрабатывает запрос на обновление токенов
// @Summary Обновление токенов по Access и Refresh токенам
// @Description Эндпойнт для обновления access и refresh токенов на основе существующего refresh токена.
// @Tags Auth
// @Accept json
// @Produce json
// @Param access_token query string true "Access токен"
// @Param refresh_token query string true "Refresh токен"
// @Success 200 {object} map[string]interface{} "successful response"
// @Failure 400 {object} map[string]interface{} "bad request"
// @Failure 401 {object} map[string]interface{} "unauthorized"
// @Failure 500 {object} map[string]interface{} "internal server error"
// @Router /auth/refresh-tokens [get]
func RefreshTokens(db *gorm.DB, c *gin.Context) {
	accessToken := c.Query("access_token")
	refreshToken := c.Query("refresh_token")

	if accessToken == "" || refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Нет access и refresh токенов"})
		return
	}

	token, err := jwt.ParseWithClaims(accessToken, &TokenPayload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный access токен", "token": err.Error()})
		return
	}

	claims, ok := token.Claims.(*TokenPayload)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Ошибка подлинности токена (claims error)"})
		return
	}

	var user models.User
	if err := db.Where("guid = ?", claims.GUID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный пользователь"})
		return
	}

	decodedRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат refresh токена"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), decodedRefreshToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный refresh токен"})
		return
	}

	clientIP := c.ClientIP()
	if user.RefreshIP != clientIP {
		helpers.SendEmailWarning(user.Email, clientIP)
	}

	newAccessToken, newRefreshToken, err := helpers.GenerateTokens(&user, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать новые токены"})
		return
	}

	hashedNewRefreshToken, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось хэшировать новый refresh токен"})
		return
	}

	user.RefreshToken = string(hashedNewRefreshToken)
	user.RefreshIP = clientIP
	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить новый refresh токен"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": base64.StdEncoding.EncodeToString([]byte(newRefreshToken)),
	})
}
