package models

import (
	Database "Bmessage_backend/database"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	GUID         string `gorm:"column:guid;unique"`
	Email        string `gorm:"column:email;unique"`
	RefreshToken string `gorm:"column:refresh_token"`
	RefreshIP    string `gorm:"column:refresh_ip"`
}

func MigrationUsertabel() {
	db, err := Database.GetDb()
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	fmt.Println("Migration executed successfully")
	sqlDB, _ := db.DB()
	sqlDB.Close()
}

func (u *User) SetRefreshToken(refreshToken string) error {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.RefreshToken = string(hashedToken)
	return nil
}

func (u *User) CheckRefreshToken(refreshToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.RefreshToken), []byte(refreshToken))
	return err == nil
}
