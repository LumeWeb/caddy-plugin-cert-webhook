package certwebhook

import "fmt"

// SSL status constants matching portal API
const (
	// SSLStatusPending indicates certificate is pending issuance
	SSLStatusPending SSLStatus = "pending"

	// SSLStatusIssuing indicates certificate is being issued
	SSLStatusIssuing SSLStatus = "issuing"

	// SSLStatusReady indicates certificate is ready and valid
	SSLStatusReady SSLStatus = "ready"

	// SSLStatusFailed indicates certificate issuance or renewal failed
	SSLStatusFailed SSLStatus = "failed"
)

// SSLStatus represents the SSL certificate status in the portal
type SSLStatus string

// mapEventToStatus converts Caddy events to portal SSL statuses
func (h *WebhookHandler) mapEventToStatus(eventType string, data *EventData) (SSLStatus, error) {
	if data == nil {
		return "", fmt.Errorf("event data is nil for event type: %s", eventType)
	}
	if data.Error != "" {
		return SSLStatusFailed, nil
	}
	
	switch eventType {
	case EventCertObtained, EventCertRenewed:
		return SSLStatusReady, nil
	case EventCertExpired:
		return SSLStatusFailed, nil
	default:
		return "", fmt.Errorf("unknown event type: %s", eventType)
	}
}
