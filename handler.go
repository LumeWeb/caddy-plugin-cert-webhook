package certwebhook

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"go.uber.org/zap"
)

const (
	LogMsgConfigValidationFailed       = "configuration validation failed"
	LogMsgFailedToSubscribeToEvents    = "failed to subscribe to events"
	LogMsgFailedToCreatePortalClient   = "failed to create portal client"
	LogMsgStarting                     = "cert_webhook app starting"
	LogMsgStarted                      = "cert_webhook app started"
	LogMsgStopping                     = "cert_webhook app stopping"
	LogMsgStopped                      = "cert_webhook app stopped"
	LogMsgWebhookDeliveryNotInitialized = "webhook delivery not initialized"
)

type CertWebhookApp struct {
	Config `json:"-"`

	logger    *zap.Logger
	ctx       caddy.Context
	portal    *PortalClient
	delivery  *WebhookDelivery
	eventsApp *caddyevents.App
}

func (CertWebhookApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "cert_webhook",
		New: func() caddy.Module { return new(CertWebhookApp) },
	}
}

func (a *CertWebhookApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	a.ctx = ctx

	a.Config.Provision()

	a.logger.Debug("config resolved",
		zap.String("portal_url", a.PortalURL),
		zap.Bool("gateway_secret_set", a.GatewaySecret != ""))

	return a.Config.Validate()
}

func (a *CertWebhookApp) Start() error {
	a.logger.Info(LogMsgStarting)

	portal, err := NewPortalClient(a.PortalURL, a.GatewaySecret)
	if err != nil {
		a.logger.Error(LogMsgFailedToCreatePortalClient, zap.Error(err))
		return err
	}
	a.portal = portal

	a.delivery = NewWebhookDelivery(a.portal.Websites(), a.logger)

	if err := a.subscribeToEvents(a.ctx); err != nil {
		a.logger.Error(LogMsgFailedToSubscribeToEvents, zap.Error(err))
		return err
	}

	a.logger.Info(LogMsgStarted,
		zap.String("portal_url", a.PortalURL))

	return nil
}

func (a *CertWebhookApp) Stop() error {
	a.logger.Info(LogMsgStopping)

	if a.delivery != nil {
		a.delivery.Wait()
	}

	if a.portal != nil {
		a.portal.Close()
	}

	a.portal = nil
	a.delivery = nil
	a.eventsApp = nil

	a.logger.Info(LogMsgStopped)
	return nil
}

func (a *CertWebhookApp) sendWebhook(domain string, status SSLStatus, errorMsg, timestamp string) error {
	if a.delivery == nil {
		a.logger.Error(LogMsgWebhookDeliveryNotInitialized)
		return fmt.Errorf("webhook delivery not initialized")
	}

	a.logger.Debug("sending webhook",
		zap.String("domain", domain),
		zap.String("status", string(status)),
		zap.String("timestamp", timestamp))

	a.delivery.deliverAsync(domain, status, errorMsg, timestamp)
	return nil
}
