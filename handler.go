package certwebhook

import (
	"context"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Log message constants
const (
	LogMsgConfigValidationFailed      = "configuration validation failed"
	LogMsgFailedToSubscribeToEvents   = "failed to subscribe to events"
	LogMsgCertWebhookHandlerProvisioned = "cert webhook handler provisioned"
	LogMsgCleaningUpCertWebhookHandler = "cleaning up cert webhook handler"
	LogMsgWebhookDeliveryNotInitialized = "webhook delivery not initialized"
)

// Interface guard to ensure WebhookHandler implements caddy.CleanerUpper.
var _ caddy.CleanerUpper = (*WebhookHandler)(nil)

// WebhookHandler is the main handler for certificate event webhooks
type WebhookHandler struct {
	// Config is the plugin configuration
	Config `json:"-"`

	// logger is the structured logger
	logger *zap.Logger

	// client is the webhook client for HTTP communication
	client *WebhookClient

	// delivery handles async webhook delivery
	delivery *WebhookDelivery

	// eventsApp holds reference to Caddy events app for cleanup
	eventsApp *caddyevents.App
}

// CaddyModule returns the Caddy module information
func (WebhookHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cert_webhook",
		New: func() caddy.Module { return new(WebhookHandler) },
	}
}

// Provision sets up the handler
func (h *WebhookHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	// Load configuration from environment variables and set defaults
	h.Config.Provision()

	// Validate configuration
	if err := h.Config.Validate(); err != nil {
		h.logger.Error(LogMsgConfigValidationFailed, zap.Error(err))
		return err
	}

	// Initialize webhook client
	h.client = NewWebhookClientWithConfig(&h.Config)

	// Initialize webhook delivery manager
	h.delivery = NewWebhookDelivery(h.client, h.logger)

	// Subscribe to certificate events
	if err := h.subscribeToEvents(ctx); err != nil {
		h.logger.Error(LogMsgFailedToSubscribeToEvents, zap.Error(err))
		return err
	}

	// Log configuration startup (without exposing secrets)
	h.logger.Info(LogMsgCertWebhookHandlerProvisioned,
		zap.String("portal_url", h.PortalURL),
		zap.Duration("timeout", h.Timeout),
		zap.Intp("retry_count", h.RetryCount),
		zap.String("gateway_secret", "***REDACTED***"))

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}

// Cleanup cleans up the handler's resources by waiting for pending webhook deliveries
// and clearing references. This implements caddy.CleanerUpper to prevent resource leaks
// on Caddy configuration reloads.
func (h *WebhookHandler) Cleanup() error {
	h.logger.Info(LogMsgCleaningUpCertWebhookHandler)

	// Wait for any pending webhook deliveries to complete
	if h.delivery != nil {
		h.delivery.Wait()
	}

	// Clear references to allow garbage collection
	h.client = nil
	h.delivery = nil
	h.eventsApp = nil

	return nil
}

// sendWebhook sends a webhook asynchronously to the portal
func (h *WebhookHandler) sendWebhook(ctx context.Context, domain string, status SSLStatus, errorMsg, timestamp string) error {
	if h.delivery == nil {
		h.logger.Error(LogMsgWebhookDeliveryNotInitialized)
		return fmt.Errorf("webhook delivery not initialized")
	}
	h.delivery.deliverAsync(ctx, domain, status, errorMsg, timestamp)
	return nil
}

