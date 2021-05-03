package model

type PingResponse struct {
	Message string `json:"message"`
}

func (r *PingResponse) Verify() bool {
	if r == nil {
		return false
	}

	return r.Message == "pong"
}
