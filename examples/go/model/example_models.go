package model

import (
	"crypto/sha256"

	"github.com/dgrijalva/jwt-go"
	"github.com/juju/errors"
)

type VerificationFields struct {
	Body        []byte
	Token       *jwt.Token
	Claims      CustomClaims
	Hash        string
	SignedToken string
}

type PingRequest struct {
	Message string `json:"message"`
}

type PingResponse struct {
	Message string `json:"message"`
}

type CustomClaims struct {
	jwt.StandardClaims
	RequestBodyHash string `json:"rbh,omitempty"`
}

func Sha256hash(body []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(body); err != nil {
		return nil, errors.Annotate(err, "writing sha256 hash failed")
	}

	return hash.Sum(nil), nil
}
