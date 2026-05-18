package certwebhook

import "fmt"

const (
	SSLStatusReady   SSLStatus = "ready"
	SSLStatusFailed  SSLStatus = "failed"
)

type SSLStatus string

func (a *CertWebhookApp) mapEventToStatus(eventType string, data *EventData) (SSLStatus, error) {
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
