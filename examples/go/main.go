package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/juju/errors"
	"github.com/wallester/integration-examples/examples/go/model"
)

func main() {
	requestBytes, err := json.Marshal(model.NewPingRequest())
	if err != nil {
		log.Fatal(errors.Annotate(err, "marshalling ping request failed"))
	}

	verificationFields, err := createToken(requestBytes)
	if err != nil {
		log.Fatal(errors.Annotate(err, "creating token failed"))
	}

	response, err := doRequest(requestBytes, verificationFields.SignedToken)
	if err != nil {
		log.Fatal(errors.Annotate(err,"doing request failed"))
	}

	if err := verifyToken(*response, *verificationFields); err != nil {
		log.Fatal(errors.Annotate(err, "verifying token failed"))
	}

	log.Println(response.Message)
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	filePath := filepath.Join("keys", "example_private")
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return nil, errors.Annotate(err, "opening file failed")
	}
	
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Annotate(err, "reading file failed")
	}

	privateKeyDecoded, _ := pem.Decode(b)
	if privateKeyDecoded == nil {
		log.Fatal("decoding private key failed")
	}

	decrypted := privateKeyDecoded.Bytes

	if x509.IsEncryptedPEMBlock(privateKeyDecoded) {
		if decrypted, err = x509.DecryptPEMBlock(privateKeyDecoded, []byte("")); err != nil {
			return nil, errors.Annotate(err, "decrypting PEM private key failed")
		}
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return nil, errors.Annotate(err, "parsing decrypted private key failed")
	}

	return parsedKey, nil
}

func hash(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}

	hash, err := sha256hash(body)
	if err != nil {
		return "", errors.Annotate(err, "creating sha256 hash failed")
	}

	return base64.StdEncoding.EncodeToString(hash), nil
}

func createToken(body []byte) (*model.VerificationFields, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return nil, errors.Annotate(err, "getting private key failed")
	}

	hash, err := hash(body)
	if err != nil {
		return nil, errors.Annotate(err, "hashing body failed")
	}

	claims := model.CustomClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  audienceID,
			ExpiresAt: time.Now().UTC().Add(15 * time.Second).Unix(),
			Issuer:    issuerID,
			Subject:   subject,
		},
		RequestBodyHash: hash,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return nil, errors.Annotate(err, "signing string failed")
	}

	return &model.VerificationFields{
		Body:        body,
		Token:       token,
		Claims:      claims,
		Hash:        hash,
		SignedToken: signedToken,
	}, nil
}

func doRequest(body []byte, token string) (*model.PingResponse, error) {
	request, err := http.NewRequest(http.MethodPost, pingURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.Annotate(err, "creating new request failed")
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Timeout: time.Second * 5,
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, errors.Annotate(err, "doing request failed")
	}

	defer response.Body.Close()

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Annotate(err, "reading body failed")
	}

	var pingResponse model.PingResponse
	if err := json.Unmarshal(b, &pingResponse); err != nil {
		return nil, errors.Annotate(err, "unmarshalling response failed")
	}

	return &pingResponse, nil
}

func verifyToken(response model.PingResponse, verificationFields model.VerificationFields) error {
	decodedHash, err := base64.StdEncoding.DecodeString(verificationFields.Hash)
	if err != nil {
		return errors.Annotate(err, "decoding hash failed")
	}

	bodyHash, err := sha256hash(verificationFields.Body)
	if err != nil {
		return errors.Annotate(err, "creating body hash failed")
	}

	if eq := bytes.Equal(decodedHash, bodyHash); !eq {
		return errors.New("decoded hash must be equal to request body hash")
	}

	if verificationFields.Token.Header["alg"] == nil {
		return errors.New("alg must be defined")
	}

	if verificationFields.Token.Header["alg"] != "RS256" {
		return errors.New("wrong signing algorithm")
	}

	if verificationFields.Claims.Audience != audienceID {
		return errors.New("invalid audience ID")
	}

	if verificationFields.Claims.Issuer != issuerID {
		return errors.New("invalid issuer ID")
	}

	if verificationFields.Claims.Subject != subject {
		return errors.New("invalid subject")
	}

	parsedToken, err := jwt.Parse(verificationFields.SignedToken, func(token *jwt.Token) (interface{}, error) {
		filePath := filepath.Join("keys", "example_public")
		file, err := os.Open(filePath)
		if err != nil {
			return nil, errors.Annotate(err, "opening file failed")
		}

		defer file.Close()

		key, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, errors.Annotate(err, "reading file failed")
		}

		return key, nil
	})
	if err != nil {
		return errors.Annotate(err, "parsing token failed")
	}

	if parsedToken.Raw != verificationFields.SignedToken {
		return errors.New("tokens are not equal")
	}

	if response.Message != "pong" {
		return errors.Errorf("Invalid response message, expected 'pong', got '%s'", response.Message)
	}

	return nil
}

// private

func sha256hash(body []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(body); err != nil {
		return nil, errors.Annotate(err, "writing sha256 hash failed")
	}

	return hash.Sum(nil), nil
}

const (
	// Replace with actual Wallester API.
	pingURL = "http://xxx.wallester.eu/v1/test/ping"
	// Replace with the actual audience ID you've got from Wallester.
	audienceID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	// Replace with the actual issuer ID you've got from Wallester.
	issuerID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	// API subject
	subject  = "api-request"
)
