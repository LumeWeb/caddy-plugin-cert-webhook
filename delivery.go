package certwebhook

import (
	"context"
	"sync"

	ipfs "go.lumeweb.com/ipfs-sdk"
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

		d.logger.Debug("delivering webhook",
			zap.String("domain", domain),
			zap.String("status", string(status)),
			zap.String("timestamp", timestamp))

		bgCtx := context.Background()

		req := ipfs.SSLStatusUpdateRequest{
			Status:    string(status),
			Timestamp: &timestamp,
		}
		if errorMsg != "" {
			req.Error = &errorMsg
		}

		err := d.websites.UpdateSSLStatusInternal(bgCtx, domain, req)
		if err != nil {
			d.logger.Error(LogMsgWebhookDeliveryFailed,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.String("timestamp", timestamp),
				zap.Error(err))
		} else {
			d.logger.Info(LogMsgWebhookDeliverySucceeded,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.String("timestamp", timestamp))
		}
	})
}

func (d *WebhookDelivery) Wait() {
	d.wg.Wait()
}
