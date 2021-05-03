package model

import (
	"github.com/dgrijalva/jwt-go"
)

type VerificationFields struct {
	Body        []byte
	Token       *jwt.Token
	Claims      CustomClaims
	Hash        string
	SignedToken string
}
