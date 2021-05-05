package http

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/juju/errors"
	"github.com/wallester/integration-examples/examples/go/model"
)

func DoRequest(body []byte, token string) (*model.Result, error) {
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

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: status code=%d", response.StatusCode)
	}

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Annotate(err, "reading response body failed")
	}

	return &model.Result{
		ResponseBody: b,
		Token:        strings.TrimPrefix(response.Header.Get("Authorization"), "Bearer "),
	}, nil
}

// private

// Replace with actual Wallester API.
const pingURL = "https://api-sandbox.wallester.eu/v1/test/ping"
