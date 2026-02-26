package certwebhook

// SSLStatusUpdateRequest is the webhook payload for SSL status updates
type SSLStatusUpdateRequest struct {
	Status    SSLStatus `json:"status"`
	Error     string    `json:"error,omitempty"`
	Timestamp string    `json:"timestamp,omitempty"`
}
