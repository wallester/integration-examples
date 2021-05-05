package main

import (
	"encoding/json"
	"log"

	"github.com/juju/errors"
	"github.com/wallester/integration-examples/examples/go/http"
	"github.com/wallester/integration-examples/examples/go/jwt"
	"github.com/wallester/integration-examples/examples/go/model"
)

func main() {
	requestBytes, err := json.Marshal(model.NewPingRequest())
	if err != nil {
		log.Fatal(errors.Annotate(err, "marshalling ping request failed"))
	}

	token, err := jwt.CreateToken(requestBytes)
	if err != nil {
		log.Fatal(errors.Annotate(err, "creating token failed"))
	}

	responseBytes, err := http.DoRequest(requestBytes, token)
	if err != nil {
		log.Fatal(errors.Annotate(err, "doing request failed"))
	}

	response, err := jwt.VerifyResponse(responseBytes)
	if err != nil {
		log.Fatal(errors.Annotate(err, "verifying response failed"))
	}

	log.Printf("\033[32mSuccess:\u001B[0m %s", response.Message)
}
