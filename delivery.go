package certwebhook

import (
	"context"
	"sync"

	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
)

// WebhookDelivery handles async webhook delivery
type WebhookDelivery struct {
	client *WebhookClient
	logger *zap.Logger
	wg     sync.WaitGroup
}

// NewWebhookDelivery creates a new webhook delivery manager
func NewWebhookDelivery(client *WebhookClient, logger *zap.Logger) *WebhookDelivery {
	return &WebhookDelivery{
		client: client,
		logger: logger,
	}
}

// Log message constants
const (
	LogMsgWebhookDeliverySucceeded = "webhook delivery succeeded"
	LogMsgWebhookDeliveryFailed    = "webhook delivery failed after retries"
	LogMsgRetrying                 = "retrying webhook delivery"
)

// deliverAsync sends webhooks asynchronously without blocking
func (d *WebhookDelivery) deliverAsync(ctx context.Context, domain string, status SSLStatus, errorMsg, timestamp string) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()

		attempts := uint(10) // Default from retry library
		if d.client.config.RetryCount != nil {
			attempts = uint(*d.client.config.RetryCount)
		}

		// Use a background context for the async delivery to prevent premature cancellation from the caller's context.
		bgCtx := context.Background()

		err := retry.Do(
			func() error {
				return d.client.sendWebhook(bgCtx, domain, status, errorMsg, timestamp)
			},
			retry.Context(bgCtx),
			retry.Attempts(attempts),
			retry.DelayType(retry.BackOffDelay),
			retry.OnRetry(func(n uint, err error) {
				d.logger.Debug(LogMsgRetrying,
					zap.Uint("attempt", n),
					zap.Error(err))
			}),
		)

		if err != nil {
			d.logger.Error(LogMsgWebhookDeliveryFailed,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.Error(err))
		} else {
			d.logger.Info(LogMsgWebhookDeliverySucceeded,
				zap.String("domain", domain),
				zap.String("status", string(status)),
				zap.String("timestamp", timestamp))
		}
	}()
}

// Wait waits for all pending webhook deliveries to complete
func (d *WebhookDelivery) Wait() {
	d.wg.Wait()
}
