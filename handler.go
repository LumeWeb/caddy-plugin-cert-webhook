package certwebhook

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	LogMsgConfigValidationFailed        = "configuration validation failed"
	LogMsgFailedToSubscribeToEvents     = "failed to subscribe to events"
	LogMsgCertWebhookHandlerProvisioned = "cert webhook handler provisioned"
	LogMsgCleaningUpCertWebhookHandler  = "cleaning up cert webhook handler"
	LogMsgWebhookDeliveryNotInitialized = "webhook delivery not initialized"
	LogMsgFailedToCreatePortalClient    = "failed to create portal client"
	LogMsgProvisionStarting             = "provision starting"
	LogMsgProvisionComplete             = "provision complete"
	LogMsgConfigResolved                = "config resolved from environment"
	LogMsgCleanupComplete               = "cleanup complete"
)

var _ caddy.CleanerUpper = (*WebhookHandler)(nil)

type WebhookHandler struct {
	Config `json:"-"`

	logger    *zap.Logger
	portal    *PortalClient
	delivery  *WebhookDelivery
	eventsApp *caddyevents.App
}

func (WebhookHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cert_webhook",
		New: func() caddy.Module { return new(WebhookHandler) },
	}
}

func (h *WebhookHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	h.logger.Debug(LogMsgProvisionStarting)

	h.Config.Provision()

	h.logger.Debug(LogMsgConfigResolved,
		zap.String("portal_url", h.PortalURL),
		zap.Bool("gateway_secret_set", h.GatewaySecret != ""))

	if err := h.Config.Validate(); err != nil {
		h.logger.Error(LogMsgConfigValidationFailed, zap.Error(err))
		return err
	}

	portal, err := NewPortalClient(h.PortalURL, h.GatewaySecret)
	if err != nil {
		h.logger.Error(LogMsgFailedToCreatePortalClient, zap.Error(err))
		return err
	}
	h.portal = portal

	h.delivery = NewWebhookDelivery(h.portal.Websites(), h.logger)

	if err := h.subscribeToEvents(ctx); err != nil {
		h.logger.Error(LogMsgFailedToSubscribeToEvents, zap.Error(err))
		return err
	}

	h.logger.Info(LogMsgCertWebhookHandlerProvisioned,
		zap.String("portal_url", h.PortalURL),
		zap.String("gateway_secret", "***REDACTED***"))

	h.logger.Debug(LogMsgProvisionComplete)

	return nil
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}

func (h *WebhookHandler) Cleanup() error {
	h.logger.Info(LogMsgCleaningUpCertWebhookHandler)

	if h.delivery != nil {
		h.delivery.Wait()
	}

	if h.portal != nil {
		h.portal.Close()
	}

	h.portal = nil
	h.delivery = nil
	h.eventsApp = nil

	h.logger.Debug(LogMsgCleanupComplete)

	return nil
}

func (h *WebhookHandler) sendWebhook(domain string, status SSLStatus, errorMsg, timestamp string) error {
	if h.delivery == nil {
		h.logger.Error(LogMsgWebhookDeliveryNotInitialized)
		return fmt.Errorf("webhook delivery not initialized")
	}

	h.logger.Debug("sending webhook",
		zap.String("domain", domain),
		zap.String("status", string(status)),
		zap.String("timestamp", timestamp))

	h.delivery.deliverAsync(domain, status, errorMsg, timestamp)
	return nil
}
