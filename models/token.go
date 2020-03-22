package models

import (
	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	Username string
	jwt.StandardClaims
}
