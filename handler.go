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

const (
	LogMsgConfigValidationFailed        = "configuration validation failed"
	LogMsgFailedToSubscribeToEvents     = "failed to subscribe to events"
	LogMsgCertWebhookHandlerProvisioned = "cert webhook handler provisioned"
	LogMsgCleaningUpCertWebhookHandler  = "cleaning up cert webhook handler"
	LogMsgWebhookDeliveryNotInitialized = "webhook delivery not initialized"
	LogMsgFailedToCreatePortalClient    = "failed to create portal client"
)

var _ caddy.CleanerUpper = (*WebhookHandler)(nil)

type WebhookHandler struct {
	Config `json:"-"`

	logger   *zap.Logger
	portal   *PortalClient
	delivery *WebhookDelivery
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

	h.Config.Provision()

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

	return nil
}

func (h *WebhookHandler) sendWebhook(ctx context.Context, domain string, status SSLStatus, errorMsg, timestamp string) error {
	if h.delivery == nil {
		h.logger.Error(LogMsgWebhookDeliveryNotInitialized)
		return fmt.Errorf("webhook delivery not initialized")
	}
	h.delivery.deliverAsync(ctx, domain, status, errorMsg, timestamp)
	return nil
}
