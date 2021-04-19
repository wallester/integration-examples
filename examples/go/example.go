package main

import (
	"bytes"
	"crypto/rsa"
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

const (
	// Replace with actual Wallester API.
	pingURL = "https://api-sandbox.wallester.eu/v1/test/ping"
	// Replace with the actual audience ID you've got from Wallester.
	audienceID = "da2b9d46-de76-498e-8746-471e8dd3d120"
	// Replace with the actual issuer ID you've got from Wallester.
	issuerID = "75fb6c0e-3c45-4208-b579-5faa2145b404"
	subject  = "api-request"
)

func main() {
	pingRequest := model.PingRequest{
		Message: "ping",
	}

	requestBytes, err := json.Marshal(pingRequest)
	if err != nil {
		log.Fatal(err)
	}

	verificationFields, err := createToken(requestBytes)
	if err != nil {
		log.Fatal(err)
	}

	response := doRequest(requestBytes, verificationFields.SignedToken)

	if err := verifyToken(response, verificationFields); err != nil {
		log.Fatal(err)
	}

	log.Print(response.Message)
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	filePath := filepath.Join("keys", "example_private")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.Annotate(err, "failed to open file")
	}
	defer func() error {
		if err = file.Close(); err != nil {
			return errors.Annotate(err, "failed to close file")
		}
		return nil
	}()

	key, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Annotate(err, "failed to read file")
	}

	privateKeyDecoded, _ := pem.Decode(key)
	if privateKeyDecoded == nil {
		log.Fatal("failed to decode private key")
	}

	decrypted := privateKeyDecoded.Bytes

	if x509.IsEncryptedPEMBlock(privateKeyDecoded) {
		if decrypted, err = x509.DecryptPEMBlock(privateKeyDecoded, []byte("")); err != nil {
			return nil, errors.Annotate(err, "failed to decrypt decoded private key")
		}
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return nil, errors.Annotate(err, "failed to parse decrypted private key")
	}

	return parsedKey, nil
}

func createHash(body []byte) (string, error) {
	if len(body) == 0 {
		return "", errors.New("length of body must be greater than zero")
	}

	hash, err := model.Sha256hash(body)
	if err != nil {
		return "", errors.Annotate(err, "creating sha256 hash failed")
	}

	return base64.StdEncoding.EncodeToString(hash), nil
}

func createToken(body []byte) (model.VerificationFields, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return model.VerificationFields{}, errors.Annotate(err, "failed to get private key")
	}

	hash, err := createHash(body)
	if err != nil {
		return model.VerificationFields{}, errors.Annotate(err, "failed to create hash from body")
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
		return model.VerificationFields{}, errors.Annotate(err, "failed to make signed string")
	}

	dataToVerify := model.VerificationFields{
		Body:        body,
		Token:       token,
		Claims:      claims,
		Hash:        hash,
		SignedToken: signedToken,
	}

	return dataToVerify, nil
}

func doRequest(body []byte, token string) model.PingResponse {
	request, err := http.NewRequest("POST", pingURL, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Timeout: time.Second * 5,
	}

	response, err := client.Do(request)
	if err != nil {
		log.Fatal("failed to send http request")
	}

	defer response.Body.Close()

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal("failed to read response body")
	}

	var pingResponse model.PingResponse
	if err := json.Unmarshal(b, &pingResponse); err != nil {
		panic(err)
	}

	return pingResponse
}

func verifyToken(response model.PingResponse, verificationFields model.VerificationFields) error {
	if response.Message != "pong" {
		return errors.New("invalid response message")
	}

	decodedHash, err := base64.StdEncoding.DecodeString(verificationFields.Hash)
	if err != nil {
		return errors.Annotate(err, "failed to decode hash")
	}

	bodyHash, err := model.Sha256hash(verificationFields.Body)
	if err != nil {
		return errors.Annotate(err, "failed to create body hash")
	}

	if err := bytes.Equal(decodedHash, bodyHash); err == false {
		return errors.New("decoded hash must be equal to request hash")
	}

	if verificationFields.Token.Header["alg"] == nil {
		return errors.New("alg must be defined")
	}

	if !(verificationFields.Claims).VerifyAudience(audienceID, false) {
		return errors.New("invalid audience ID")
	}

	if !(verificationFields.Claims).VerifyIssuer(issuerID, false) {
		return errors.New("invalid issuer ID")
	}

	parsedToken, err := jwt.Parse(verificationFields.SignedToken, func(token *jwt.Token) (interface{}, error) {
		filePath := filepath.Join("keys", "example_public")
		file, err := os.Open(filePath)
		if err != nil {
			return nil, errors.Annotate(err, "failed to open file")
		}

		key, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, errors.Annotate(err, "failed to read file")
		}

		return key, nil
	})

	if parsedToken != nil {
		if parsedToken.Raw != verificationFields.SignedToken {
			return errors.New("tokens are not equal")
		}
	}

	return nil
}
