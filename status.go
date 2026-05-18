package certwebhook

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

const (
	SSLStatusReady   SSLStatus = "ready"
	SSLStatusFailed  SSLStatus = "failed"
	SSLStatusIssuing SSLStatus = "issuing"
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

type certStatusFunc func(domain string) SSLStatus

var defaultCertStatusFn certStatusFunc = func(domain string) SSLStatus {
	certs := caddytls.AllMatchingCertificates(domain)
	if len(certs) == 0 {
		return SSLStatusIssuing
	}

	now := time.Now()
	for _, cert := range certs {
		if cert.Leaf == nil {
			continue
		}
		if !cert.Expired() && now.After(cert.Leaf.NotBefore) {
			return SSLStatusReady
		}
	}

	return SSLStatusFailed
}
