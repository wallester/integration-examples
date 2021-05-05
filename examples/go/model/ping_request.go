package model

type PingRequest struct {
	Message string `json:"message"`
}

func NewPingRequest() *PingRequest {
	return &PingRequest{
		Message: "ping",
	}
}
