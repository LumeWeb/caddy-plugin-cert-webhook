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

// Caddy event names for certificate lifecycle
const (
	// EventCertObtained is fired when a certificate is first obtained
	EventCertObtained = "cert_obtained"

	// EventCertRenewed is fired when a certificate is renewed
	EventCertRenewed = "cert_renewed"

	// EventCertExpired is fired when a certificate expires
	EventCertExpired = "cert_expired"
)

// Log message constants
const (
	LogMsgEventsAppNotAvailable      = "events app not available"
	LogMsgEventsAppNotExpectedType   = "events app is not of expected type"
	LogMsgSubscribedToCertObtained   = "subscribed to cert_obtained event"
	LogMsgSubscribedToCertRenewed    = "subscribed to cert_renewed event"
	LogMsgSubscribedToCertExpired    = "subscribed to cert_expired event"
	LogMsgUnknownEventType          = "unknown event type"
	LogMsgFailedToExtractEventData   = "failed to extract event data"
	LogMsgFailedToMapEventToStatus   = "failed to map event to status"
	LogMsgCertificateEventProcessed = "certificate event processed"
)

// EventData represents certificate event data from Caddy
type EventData struct {
	// Domain is the certificate domain name
	Domain string `json:"domain"`

	// Timestamp is when the event occurred (ISO 8601 format)
	Timestamp string `json:"timestamp"`

	// Error is any error that occurred during certificate operation
	Error string `json:"error,omitempty"`

	// Raw is the raw event data for debugging
	Raw map[string]any `json:"-"`

	// EventType is the type of event (cert_obtained, cert_renewed, cert_expired)
	EventType string `json:"event_type"`
}

// Event handlers for certificate lifecycle events

// subscribeToEvents registers handlers for certificate events
func (h *CertWebhookApp) subscribeToEvents(ctx caddy.Context) error {
	// Get the events app from context
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

	// Store reference for cleanup
	h.eventsApp = eventsApp

	// Subscribe to cert_obtained event
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

	return nil
}

// Handle implements caddyevents.Handler interface to process certificate events
func (h *CertWebhookApp) Handle(ctx context.Context, data caddy.Event) error {
	eventName := data.Name()

	switch eventName {
	case EventCertObtained, EventCertRenewed, EventCertExpired:
		return h.handleCertEvent(eventName, data)
	default:
		h.logger.Warn(LogMsgUnknownEventType, zap.String("event", eventName))
		return nil
	}
}

// handleCertEvent processes certificate lifecycle events (obtained, renewed, expired)
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

	h.logger.Info(LogMsgCertificateEventProcessed,
		zap.String("event_type", eventType),
		zap.String("domain", eventData.Domain),
		zap.String("status", string(status)),
		zap.String("timestamp", eventData.Timestamp))

	return h.sendWebhook(eventData.Domain, status, eventData.Error, eventData.Timestamp)
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
