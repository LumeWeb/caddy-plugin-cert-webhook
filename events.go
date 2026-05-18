package certwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"go.uber.org/zap"
)

const (
	EventCertObtained = "cert_obtained"

	EventCertRenewed = "cert_renewed"

	EventCertExpired = "cert_expired"

	EventTLSGetCertificate = "tls_get_certificate"
)

const (
	LogMsgEventsAppNotAvailable      = "events app not available"
	LogMsgEventsAppNotExpectedType   = "events app is not of expected type"
	LogMsgSubscribedToCertObtained   = "subscribed to cert_obtained event"
	LogMsgSubscribedToCertRenewed    = "subscribed to cert_renewed event"
	LogMsgSubscribedToCertExpired    = "subscribed to cert_expired event"
	LogMsgSubscribedToTLSGetCert     = "subscribed to tls_get_certificate event"
	LogMsgUnknownEventType          = "unknown event type"
	LogMsgFailedToExtractEventData   = "failed to extract event data"
	LogMsgFailedToMapEventToStatus   = "failed to map event to status"
	LogMsgCertificateEventProcessed = "certificate event processed"
	LogMsgTLSGetCertThrottled       = "tls_get_certificate event throttled"
	LogMsgTLSGetCertProcessed       = "tls_get_certificate event processed"
)

type EventData struct {
	Domain string `json:"domain"`

	Timestamp string `json:"timestamp"`

	Error string `json:"error,omitempty"`

	Raw map[string]any `json:"-"`

	EventType string `json:"event_type"`
}

func (h *CertWebhookApp) subscribeToEvents(ctx caddy.Context) error {
	eventsAppIface, err := ctx.App("events")
	if err != nil {
		h.logger.Warn(LogMsgEventsAppNotAvailable, zap.Error(err))
		return nil
	}

	eventsApp, ok := eventsAppIface.(*caddyevents.App)
	if !ok {
		h.logger.Warn(LogMsgEventsAppNotExpectedType)
		return nil
	}

	h.eventsApp = eventsApp

	if err := eventsApp.On(EventCertObtained, h); err != nil {
		return fmt.Errorf("failed to subscribe to cert_obtained event: %w", err)
	}
	h.logger.Info(LogMsgSubscribedToCertObtained)

	if err := eventsApp.On(EventCertRenewed, h); err != nil {
		return fmt.Errorf("failed to subscribe to cert_renewed event: %w", err)
	}
	h.logger.Info(LogMsgSubscribedToCertRenewed)

	if err := eventsApp.On(EventCertExpired, h); err != nil {
		return fmt.Errorf("failed to subscribe to cert_expired event: %w", err)
	}
	h.logger.Info(LogMsgSubscribedToCertExpired)

	if err := eventsApp.On(EventTLSGetCertificate, h); err != nil {
		return fmt.Errorf("failed to subscribe to tls_get_certificate event: %w", err)
	}
	h.logger.Info(LogMsgSubscribedToTLSGetCert)

	return nil
}

func (h *CertWebhookApp) Handle(ctx context.Context, data caddy.Event) error {
	eventName := data.Name()

	switch eventName {
	case EventCertObtained, EventCertRenewed, EventCertExpired:
		return h.handleCertEvent(eventName, data)
	case EventTLSGetCertificate:
		return h.handleTLSGetCertificateEvent(data)
	default:
		h.logger.Warn(LogMsgUnknownEventType, zap.String("event", eventName))
		return nil
	}
}

func (h *CertWebhookApp) handleCertEvent(eventType string, data caddy.Event) error {
	h.logger.Debug("handling cert event", zap.String("event_type", eventType))

	eventData, err := h.extractEventData(eventType, data)
	if err != nil {
		h.logger.Error(LogMsgFailedToExtractEventData,
			zap.String("event_type", eventType),
			zap.Error(err))
		return err
	}

	status, err := h.mapEventToStatus(eventType, eventData)
	if err != nil {
		h.logger.Error(LogMsgFailedToMapEventToStatus,
			zap.String("event_type", eventType),
			zap.Error(err))
		return err
	}

	if !h.shouldSend(eventData.Domain, status) {
		h.logger.Debug("cert event throttled",
			zap.String("event_type", eventType),
			zap.String("domain", eventData.Domain),
			zap.String("status", string(status)))
		return nil
	}

	h.logger.Info(LogMsgCertificateEventProcessed,
		zap.String("event_type", eventType),
		zap.String("domain", eventData.Domain),
		zap.String("status", string(status)),
		zap.String("timestamp", eventData.Timestamp))

	return h.sendWebhook(eventData.Domain, status, eventData.Error, eventData.Timestamp)
}

func (h *CertWebhookApp) handleTLSGetCertificateEvent(data caddy.Event) error {
	domain, err := extractDomainFromClientHello(data)
	if err != nil {
		h.logger.Debug("failed to extract domain from tls_get_certificate", zap.Error(err))
		return nil
	}

	status := h.certStatusFn(domain)

	if !h.shouldSend(domain, status) {
		h.logger.Debug(LogMsgTLSGetCertThrottled,
			zap.String("domain", domain),
			zap.String("status", string(status)))
		return nil
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	h.logger.Info(LogMsgTLSGetCertProcessed,
		zap.String("domain", domain),
		zap.String("status", string(status)),
		zap.String("timestamp", timestamp))

	return h.sendWebhook(domain, status, "", timestamp)
}

func extractDomainFromClientHello(event caddy.Event) (string, error) {
	if len(event.Data) == 0 {
		return "", fmt.Errorf("event data is empty")
	}

	raw := make(map[string]any)
	if err := decodeJSON(event.Data, &raw); err != nil {
		return "", fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	clientHello, ok := raw["client_hello"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("client_hello not found in event data")
	}

	serverName, ok := clientHello["ServerName"].(string)
	if !ok || serverName == "" {
		return "", fmt.Errorf("ServerName not found in client_hello")
	}

	return serverName, nil
}

// extractEventData extracts domain, timestamp, and error information from Caddy event data
func (h *CertWebhookApp) extractEventData(eventType string, event caddy.Event) (*EventData, error) {
	data := &EventData{
		EventType: eventType,
		Raw:       make(map[string]any),
	}

	if len(event.Data) == 0 {
		return nil, fmt.Errorf("event data is empty")
	}

	if err := decodeJSON(event.Data, &data.Raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	h.logger.Debug("raw event data decoded", zap.Any("data", data.Raw))

	if ts, ok := data.Raw["ts"].(float64); ok {
		sec := int64(ts)
		nsec := int64((ts - float64(sec)) * 1e9)
		data.Timestamp = time.Unix(sec, nsec).UTC().Format(time.RFC3339)
	} else {
		data.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if domain, ok := data.Raw["domain"].(string); ok {
		data.Domain = domain
	} else if san, ok := data.Raw["sans"].([]any); ok && len(san) > 0 {
		if d, ok := san[0].(string); ok {
			data.Domain = d
		}
	}

	if data.Domain == "" {
		h.logger.Debug("no domain found in event data")
		return nil, fmt.Errorf("no domain found in event data")
	}

	if err, ok := data.Raw["error"].(string); ok {
		data.Error = err
	}

	return data, nil
}

// decodeJSON decodes JSON data from map[string]any to target
func decodeJSON(data map[string]any, target any) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonBytes, target)
}
