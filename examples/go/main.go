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
	"strings"
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

	token, err := createToken(requestBytes)
	if err != nil {
		log.Fatal(errors.Annotate(err, "creating token failed"))
	}

	responseBytes, err := doRequest(requestBytes, token)
	if err != nil {
		log.Fatal(errors.Annotate(err, "doing request failed"))
	}

	response, err := verifyResponse(responseBytes)
	if err != nil {
		log.Fatal(errors.Annotate(err, "verifying response failed"))
	}

	log.Printf("\033[32mSuccess:\u001B[0m %s", response.Message)
}

func readPrivateKey() (*rsa.PrivateKey, error) {
	filePath := filepath.Join("..", "..", "keys", "example_private")
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return nil, errors.Annotate(err, "opening file failed")
	}

	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Annotate(err, "reading file failed")
	}

	decrypted, err := decodePEMBlock(b)
	if err != nil {
		return nil, errors.Annotate(err, "decoding PEM block failed")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return nil, errors.Annotate(err, "parsing decrypted private key failed")
	}

	return parsedKey, nil
}

func createToken(body []byte) (string, error) {
	privateKey, err := readPrivateKey()
	if err != nil {
		return "", errors.Annotate(err, "getting private key failed")
	}

	hash, err := calculateRequestBodyHash(body)
	if err != nil {
		return "", errors.Annotate(err, "hashing body failed")
	}

	claims := model.CustomClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  audienceID,
			ExpiresAt: time.Now().UTC().Add(maxExpirationTime).Unix(),
			Issuer:    issuerID,
			Subject:   subject,
		},
		RequestBodyHash: hash,
	}

	signer := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := signer.SignedString(privateKey)
	if err != nil {
		return "", errors.Annotate(err, "signing string failed")
	}

	return signedToken, nil
}

type result struct {
	Token        string
	ResponseBody []byte
}

func doRequest(body []byte, token string) (*result, error) {
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

	if response.StatusCode != 200 {
		return nil, errors.Errorf("unexpected status code: status code=%d", response.StatusCode)
	}

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Annotate(err, "reading response body failed")
	}

	return &result{
		ResponseBody: b,
		Token:        strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer "),
	}, nil
}

func verifyResponse(result *result) (*model.PingResponse, error) {
	parser := &jwt.Parser{
		SkipClaimsValidation: true,
	}

	if _, err := parser.Parse(result.Token, func(token *jwt.Token) (interface{}, error) {
		if token == nil {
			return nil, errors.New("token is empty")
		}

		claims := token.Claims.(jwt.MapClaims)
		if !claims.VerifyAudience(issuerID, true) {
			return nil, errors.New("invalid audience ID")
		}

		if !claims.VerifyIssuer(audienceID, true) {
			return nil, errors.New("invalid issuer ID")
		}

		if !claims.VerifyExpiresAt(time.Now().UTC().Unix(), true) {
			return nil, errors.New("invalid token expiration time")
		}

		if claims["sub"] != subject {
			return nil, errors.New("invalid subject")
		}

		if token.Header["alg"] == nil || token.Header["alg"] != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid token signing algorithm")
		}

		expectedRBH, err := calculateRequestBodyHash(result.ResponseBody)
		if err != nil {
			return nil, errors.Annotate(err, "hashing httpResponse body failed")
		}

		if rbh, ok := claims["rbh"].(string); !ok || rbh != expectedRBH {
			return nil, errors.New("invalid rbh received")
		}

		filePath := filepath.Join("..", "..", "keys", "example_wallester_public")
		file, err := os.Open(filepath.Clean(filePath))
		if err != nil {
			return nil, errors.Annotate(err, "opening file failed")
		}

		defer file.Close()

		b, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, errors.Annotate(err, "reading file failed")
		}

		decrypted, err := decodePEMBlock(b)
		if err != nil {
			return nil, errors.Annotate(err, "decoding PEM block failed")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(decrypted)
		if err != nil {
			return nil, errors.Annotate(err, "parsing decrypted public key failed")
		}

		return parsedKey, nil
	}); err != nil {
		return nil, errors.Annotate(err, "parsing token failed")
	}

	var response model.PingResponse
	if err := json.Unmarshal(result.ResponseBody, &response); err != nil {
		return nil, errors.Annotate(err, "unmarshalling body failed")
	}

	if !response.Verify() {
		return nil, errors.Errorf("Invalid response message, expected 'pong', got '%s'", response.Message)
	}

	return &response, nil
}

func calculateRequestBodyHash(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}

	hash, err := sha256hash(body)
	if err != nil {
		return "", errors.Annotate(err, "creating sha256 hash failed")
	}

	return base64.StdEncoding.EncodeToString(hash), nil
}

func sha256hash(body []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(body); err != nil {
		return nil, errors.Annotate(err, "writing sha256 hash failed")
	}

	return hash.Sum(nil), nil
}

func decodePEMBlock(block []byte) ([]byte, error) {
	decodedKey, _ := pem.Decode(block)
	if decodedKey == nil {
		log.Fatal("decoding block failed")
	}

	var (
		decrypted = decodedKey.Bytes
		err       error
	)

	if x509.IsEncryptedPEMBlock(decodedKey) {
		if decrypted, err = x509.DecryptPEMBlock(decodedKey, []byte("")); err != nil {
			return nil, errors.Annotate(err, "decrypting PEM key failed")
		}
	}

	return decrypted, nil
}

const (
	// Replace with actual Wallester API.
	pingURL = "https://api-sandbox.wallester.eu/v1/test/ping"
	// Replace with the actual audience ID you've got from Wallester.
	audienceID = "da2b9d46-de76-498e-8746-471e8dd3d120"
	// Replace with the actual issuer ID you've got from Wallester.
	issuerID = "75fb6c0e-3c45-4208-b579-5faa2145b404"
	// API subject
	subject = "api-request"
	// Maximum JWT token expiration time
	maxExpirationTime = 60 * time.Second
)
