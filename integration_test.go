package certwebhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestWebhookDelivery_FullIntegration(t *testing.T) {
	t.Run("successful webhook delivery on cert obtained", func(t *testing.T) {
		var receivedSecret string
		var receivedPayload SSLStatusUpdateRequest
		var receivedPath string
		var mu sync.Mutex
		
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			
			receivedSecret = r.Header.Get(GatewaySecretHeader)
			receivedPath = r.URL.Path
			
			var payload SSLStatusUpdateRequest
			err := json.NewDecoder(r.Body).Decode(&payload)
			assert.NoError(t, err)
			receivedPayload = payload
			
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		
		config := &Config{
			PortalURL:     server.URL,
			GatewaySecret: "test-secret",
			Timeout:       5 * time.Second,
			RetryCount:    new(5),
		}
		client := NewWebhookClientWithConfig(config)
		obs, _ := observer.New(zap.DebugLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ts := time.Now()
		delivery.deliverAsync(ctx, "example.com", SSLStatusReady, "", ts.Format(time.RFC3339))
		
		delivery.wg.Wait()
		
		mu.Lock()
		assert.Equal(t, "test-secret", receivedSecret)
		assert.Equal(t, "/internal/websites/example.com/ssl-status", receivedPath)
		assert.Equal(t, SSLStatusReady, receivedPayload.Status)
		assert.Empty(t, receivedPayload.Error)
		assert.NotEmpty(t, receivedPayload.Timestamp)
		mu.Unlock()
	})
	
	t.Run("webhook delivery with error status", func(t *testing.T) {
		var receivedPayload SSLStatusUpdateRequest
		var mu sync.Mutex
		
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			
			var payload SSLStatusUpdateRequest
			err := json.NewDecoder(r.Body).Decode(&payload)
			assert.NoError(t, err)
			receivedPayload = payload
			
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		
		client := NewWebhookClientWithConfig(&Config{PortalURL: server.URL, GatewaySecret: "test-secret", Timeout: 5 * time.Second, RetryCount: new(5)})
		obs, _ := observer.New(zap.InfoLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		errorMsg := "certificate validation failed"
		delivery.deliverAsync(ctx, "example.com", SSLStatusFailed, errorMsg, time.Now().Format(time.RFC3339))
		
		delivery.wg.Wait()
		
		mu.Lock()
		assert.Equal(t, SSLStatusFailed, receivedPayload.Status)
		assert.Equal(t, errorMsg, receivedPayload.Error)
		mu.Unlock()
	})
	
	t.Run("webhook delivery with retry on transient error", func(t *testing.T) {
		attempts := 0
		var mu sync.Mutex
		
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		
		client := NewWebhookClientWithConfig(&Config{PortalURL: server.URL, GatewaySecret: "test-secret", Timeout: 5 * time.Second, RetryCount: new(5)})
		obs, _ := observer.New(zap.InfoLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		delivery.deliverAsync(ctx, "example.com", SSLStatusReady, "", time.Now().Format(time.RFC3339))
		
		delivery.wg.Wait()
		
		mu.Lock()
		assert.Equal(t, 3, attempts)
		mu.Unlock()
	})
	
	t.Run("webhook delivery fails after max retries", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		
		client := NewWebhookClientWithConfig(&Config{PortalURL: server.URL, GatewaySecret: "test-secret", Timeout: 5 * time.Second, RetryCount: new(5)})
		obs, logs := observer.New(zap.InfoLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		delivery.deliverAsync(ctx, "example.com", SSLStatusReady, "", time.Now().Format(time.RFC3339))
		
		delivery.wg.Wait()
		
		failureLogs := 0
		for _, entry := range logs.All() {
			if entry.Message == LogMsgWebhookDeliveryFailed {
				failureLogs++
			}
		}
		assert.Equal(t, 1, failureLogs, "expected failure log after max retries")
	})
	
	t.Run("multiple concurrent webhook deliveries", func(t *testing.T) {
		var receivedDomains []string
		var mu sync.Mutex
		
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			
			receivedDomains = append(receivedDomains, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		
		client := NewWebhookClientWithConfig(&Config{PortalURL: server.URL, GatewaySecret: "test-secret", Timeout: 5 * time.Second, RetryCount: new(5)})
		obs, _ := observer.New(zap.InfoLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		domains := []string{"example1.com", "example2.com", "example3.com"}
		for _, domain := range domains {
			delivery.deliverAsync(ctx, domain, SSLStatusReady, "", time.Now().Format(time.RFC3339))
		}
		
		delivery.wg.Wait()
		
		mu.Lock()
		assert.Len(t, receivedDomains, len(domains))
		mu.Unlock()
	})
	
	t.Run("context cancellation during delivery", func(t *testing.T) {
		delayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer delayServer.Close()
		
		client := NewWebhookClientWithConfig(&Config{PortalURL: delayServer.URL, GatewaySecret: "test-secret", Timeout: 5 * time.Second, RetryCount: new(5)})
		obs, logs := observer.New(zap.InfoLevel)
		logger := zap.New(obs)
		delivery := NewWebhookDelivery(client, logger)
		
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		
		ts := time.Now()
		delivery.deliverAsync(ctx, "example.com", SSLStatusReady, "", ts.Format(time.RFC3339))
		
		delivery.wg.Wait()
		
		successLogs := 0
		for _, entry := range logs.All() {
			if entry.Message == LogMsgWebhookDeliverySucceeded {
				successLogs++
			}
		}
		assert.Equal(t, 1, successLogs, "expected successful delivery despite context cancellation")
	})
}
