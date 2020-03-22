package models

/*
	Code largely borrowed from https://github.com/adigunhammedolalekan/go-contacts
*/

import (
	"os"
	"strings"

	"github.com/avoulk/go-schedule/utils"
	"github.com/avoulk/go-schedule/extras"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	gorm.Model
	Username  string `json:"username"`
	Password  string
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"family_name`
	Birthdate time   `json:"birthdate"`
	Token     string `json:"token"`
}

// Validates an account
func (account *Account) Validate() (map[string]interface{}, bool) {

	if !strings.Contains(account.Email, "@") and {
		return utils.Message(false, "Email address is required"), false
	}

	if account.Username == nil {
		return utils.Message(false, "Username is required"), false
	}

	password_ok, _ = extras.Check_pwd(account.Password)
	if !password_ok {
		return utils.Message(false, "Password is not safe enough"), false
	}

	//Email must be unique
	temp := &Account{}

	//check for errors and duplicate emails
	err := GetDB().Table("accounts").Where("email = ?", account.Email).Or("username = ?", account.Username).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return utils.Message(false, "Connection error. Please retry"), false
	}
	if temp.Email != "" {
		return utils.Message(false, "Email address already in use by another user."), false
	} else if temp.Username != "" {
		return utils.Message(false, "Username already in use by another user."), false
	}

	return utils.Message(false, "Requirement passed"), true
}

// Creates a new account 
func (account *Account) Create() map[string]interface{} {

	if resp, ok := account.Validate(); !ok {
		return resp
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	GetDB().Create(account)

	if account.ID <= 0 {
		return utils.Message(false, "Failed to create account, connection error.")
	}

	//Create new JWT token for the newly registered account
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString

	// Next, delete the password so that it does not get exposed in any way
	account.Password = ""

	response := utils.Message(true, "Account has been created")
	response["account"] = account
	return response
}

// Login logs a user in based on a username/email and a password
func Login(email, username, password string) map[string]interface{} {

	account := &Account{}
	err := GetDB().Table("accounts").Where("email = ?", email).Or("username = ?", username).First(account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Message(false, "Email address not found")
		}
		return utils.Message(false, "Connection error. Please retry")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		return utils.Message(false, "Invalid login credentials. Please try again")
	}
	//Worked! Logged In
	account.Password = ""

	//Create JWT token
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString //Store the token in the response

	resp := utils.Message(true, "Logged In")
	resp["account"] = account
	return resp
}
