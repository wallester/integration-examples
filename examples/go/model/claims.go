package model

import "github.com/dgrijalva/jwt-go"

type CustomClaims struct {
	jwt.StandardClaims
	RequestBodyHash string `json:"rbh,omitempty"`
}
