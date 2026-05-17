package certwebhook

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	ipfs "go.lumeweb.com/ipfs-sdk"
	servicemocks "go.lumeweb.com/ipfs-sdk/mocks/services"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestWebhookDelivery_SuccessfulDelivery(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	obs, _ := observer.New(zap.DebugLevel)
	logger := zap.New(obs)
	delivery := NewWebhookDelivery(mockSvc, logger)

	ts := time.Now().Format(time.RFC3339)
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		context.Background(),
		"example.com",
		ipfs.SSLStatusUpdateRequest{
			Status:    string(SSLStatusReady),
			Timestamp: &ts,
		},
	).Return(nil)

	delivery.deliverAsync(context.Background(), "example.com", SSLStatusReady, "", ts)
	delivery.Wait()
}

func TestWebhookDelivery_ErrorStatus(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	obs, _ := observer.New(zap.InfoLevel)
	logger := zap.New(obs)
	delivery := NewWebhookDelivery(mockSvc, logger)

	ts := time.Now().Format(time.RFC3339)
	errorMsg := "certificate validation failed"
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		context.Background(),
		"example.com",
		ipfs.SSLStatusUpdateRequest{
			Status:    string(SSLStatusFailed),
			Error:     &errorMsg,
			Timestamp: &ts,
		},
	).Return(nil)

	delivery.deliverAsync(context.Background(), "example.com", SSLStatusFailed, errorMsg, ts)
	delivery.Wait()
}

func TestWebhookDelivery_FailedDelivery(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	obs, logs := observer.New(zap.InfoLevel)
	logger := zap.New(obs)
	delivery := NewWebhookDelivery(mockSvc, logger)

	ts := time.Now().Format(time.RFC3339)
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		context.Background(),
		"example.com",
		ipfs.SSLStatusUpdateRequest{
			Status:    string(SSLStatusReady),
			Timestamp: &ts,
		},
	).Return(fmt.Errorf("internal server error"))

	delivery.deliverAsync(context.Background(), "example.com", SSLStatusReady, "", ts)
	delivery.Wait()

	failureLogs := 0
	for _, entry := range logs.All() {
		if entry.Message == LogMsgWebhookDeliveryFailed {
			failureLogs++
		}
	}
	assert.Equal(t, 1, failureLogs, "expected failure log after delivery error")
}

func TestWebhookDelivery_MultipleConcurrentDeliveries(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	obs, _ := observer.New(zap.InfoLevel)
	logger := zap.New(obs)
	delivery := NewWebhookDelivery(mockSvc, logger)

	domains := []string{"example1.com", "example2.com", "example3.com"}
	for _, domain := range domains {
		ts := time.Now().Format(time.RFC3339)
		d := domain
		mockSvc.EXPECT().UpdateSSLStatusInternal(
			context.Background(),
			d,
			ipfs.SSLStatusUpdateRequest{
				Status:    string(SSLStatusReady),
				Timestamp: &ts,
			},
		).Return(nil)
		delivery.deliverAsync(context.Background(), domain, SSLStatusReady, "", ts)
	}

	delivery.Wait()
}
