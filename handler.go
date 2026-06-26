package certwebhook

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"go.uber.org/zap"
)

const (
	LogMsgConfigValidationFailed        = "configuration validation failed"
	LogMsgFailedToSubscribeToEvents     = "failed to subscribe to events"
	LogMsgFailedToCreatePortalClient    = "failed to create portal client"
	LogMsgStarting                      = "cert_webhook app starting"
	LogMsgStarted                       = "cert_webhook app started"
	LogMsgStopping                      = "cert_webhook app stopping"
	LogMsgStopped                       = "cert_webhook app stopped"
	LogMsgWebhookDeliveryNotInitialized = "webhook delivery not initialized"
	LogMsgWebhookThrottled              = "webhook throttled for domain"
	LogMsgSkippingIPAddress             = "skipping webhook for IP address"
)

const defaultThrottleInterval = 5 * time.Minute

type lastSentEntry struct {
	status SSLStatus
	time   time.Time
}

type throttleMap struct {
	mu       sync.Mutex
	lastSent map[string]lastSentEntry
	interval time.Duration
}

type CertWebhookApp struct {
	Config `json:"-"`

	logger           *zap.Logger
	ctx              caddy.Context
	portal           *PortalClient
	delivery         *WebhookDelivery
	eventsApp        *caddyevents.App
	throttle         *throttleMap
	throttleInterval time.Duration
	certStatusFn     certStatusFunc
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

	a.throttleInterval = a.Config.throttleInterval()
	a.throttle = &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: a.throttleInterval,
	}
	a.certStatusFn = defaultCertStatusFn

	initMetrics(a.ctx.GetMetricsRegistry())
	initTracer()

	a.logger.Debug("config resolved",
		zap.String("portal_url", a.PortalURL),
		zap.Bool("gateway_secret_set", a.GatewaySecret != ""),
		zap.Duration("throttle_interval", a.throttleInterval))

	if err := a.Config.Validate(); err != nil {
		return err
	}

	// Subscribe to events during provisioning, before the events app starts.
	// Caddy's event bus rejects new subscriptions after Start() is called.
	if err := a.subscribeToEvents(ctx); err != nil {
		a.logger.Error(LogMsgFailedToSubscribeToEvents, zap.Error(err))
		return err
	}

	return nil
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
	a.throttle = nil

	a.logger.Info(LogMsgStopped)
	return nil
}

func (a *CertWebhookApp) sendWebhook(domain string, status SSLStatus, errorMsg, timestamp string) error {
	if shouldSkipDomain(domain) {
		a.logger.Debug(LogMsgSkippingIPAddress,
			zap.String("domain", domain))
		return nil
	}

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

// shouldSkipDomain returns true for raw IP addresses. Caddy issues certs
// for the gateway's listen address (e.g. 104.243.38.32) and the cert_webhook
// would otherwise fire a webhook to the portal, which 404s because there's no
// website record for an IP.
func shouldSkipDomain(domain string) bool {
	return net.ParseIP(domain) != nil
}

func (a *CertWebhookApp) shouldSend(domain string, status SSLStatus) bool {
	if a.throttle == nil {
		return true
	}
	return a.throttle.checkAndMark(domain, status)
}

func (tm *throttleMap) checkAndMark(domain string, status SSLStatus) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	last, ok := tm.lastSent[domain]
	if !ok || last.status != status || time.Since(last.time) >= tm.interval {
		tm.lastSent[domain] = lastSentEntry{status: status, time: time.Now()}
		return true
	}
	return false
}
