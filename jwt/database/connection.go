package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"jwt/models"
)

var DB *gorm.DB

func Connect() {

	connection, err := gorm.Open(postgres.Open("host=localhost user=postgres password=postgres dbname=jwt-auth port=5432 sslmode=disable"), &gorm.Config{})

	if err != nil {
		panic("could not connect to database.")
	}

	DB = connection

	connection.AutoMigrate(&models.User{})

}
