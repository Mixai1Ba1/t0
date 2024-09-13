package helpers

import (
	"Bmessage_backend/models"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenPayload struct {
	GUID string `json:"guid"`
	IP   string `json:"ip"`
	jwt.StandardClaims
}

func GenerateTokens(user *models.User, clientIP string) (string, string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &TokenPayload{
		GUID: user.GUID,
		IP:   clientIP,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Hour).Unix(), // access исчезает через 15 часов
		},
	})

	accessSecret := []byte(os.Getenv("ACCESS_SECRET"))
	accessTokenString, err := accessToken.SignedString([]byte(accessSecret))
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	err = user.SetRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshToken, nil
}

func GenerateRefreshToken() (string, error) {
	refreshToken, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	return refreshToken, nil
}

func generateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid length")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	randomString := base64.StdEncoding.EncodeToString(bytes)

	if len(randomString) > length {
		randomString = randomString[:length]
	}

	return randomString, nil
}
