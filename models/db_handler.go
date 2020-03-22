package models

import (
	"fmt"
	"os"

	logging "github.com/golang/glog"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var db *gorm.DB

func init() {
	username := os.Getenv("POSTRES_USER")
	password := os.Getenv("POSTRES_PASSWORD")
	dbName := os.Getenv("POSTRES_DB")
	dbHost := os.Getenv("POSTRES_HOST")

	dbUri := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s", dbHost, username, dbName, password)

	conn, err := gorm.Open("postgres", dbUri)
	if err != nil {
		logging.Error("Could not connect to the DB")
		logging.Fatalln(error)
	}

	db = conn
	// db.Debug().AutoMigrate(&Account{}, &Contact{}) //Database migration
	db.Debug().AutoMigrate(&Contact, &Token{})
}

func GetSession() *gorm.DB {
	return db
}
