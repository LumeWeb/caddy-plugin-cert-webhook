package certwebhook

import (
	"context"
	"sync"

	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type WebhookDelivery struct {
	websites ipfs.WebsitesService
	logger   *zap.Logger
	wg       sync.WaitGroup
	sem      chan struct{}
}

func NewWebhookDelivery(websites ipfs.WebsitesService, logger *zap.Logger) *WebhookDelivery {
	return &WebhookDelivery{
		websites: websites,
		logger:   logger,
		sem:      make(chan struct{}, 100),
	}
}

const (
	LogMsgWebhookDeliverySucceeded = "webhook delivery succeeded"
	LogMsgWebhookDeliveryFailed    = "webhook delivery failed"
)

func (d *WebhookDelivery) deliverAsync(domain string, status SSLStatus, errorMsg, timestamp string) {
	d.wg.Go(func() {
		d.sem <- struct{}{}
		defer func() { <-d.sem }()

		bgCtx := context.Background()
		ctx, span := startSpan(bgCtx, "cert_webhook.deliver_webhook",
			attribute.String("domain", domain),
			attribute.String("status", string(status)))
		defer span.End()

		d.logger.Debug("delivering webhook",
			zap.String("domain", domain),
			zap.String("status", string(status)),
			zap.String("timestamp", timestamp))

		req := ipfs.SSLStatusUpdateRequest{
			Status:    string(status),
			Timestamp: &timestamp,
		}
		if errorMsg != "" {
			req.Error = &errorMsg
		}

		err := d.websites.UpdateSSLStatusInternal(ctx, domain, req)
		if err != nil {
			d.logger.Error(LogMsgWebhookDeliveryFailed,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.String("timestamp", timestamp),
				zap.Error(err))
			recordWebhookDelivery(domain, status, false)
			endSpanWithError(span, err)
		} else {
			d.logger.Info(LogMsgWebhookDeliverySucceeded,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.String("timestamp", timestamp))
			recordWebhookDelivery(domain, status, true)
		}
	})
}

func (d *WebhookDelivery) Wait() {
	d.wg.Wait()
}
