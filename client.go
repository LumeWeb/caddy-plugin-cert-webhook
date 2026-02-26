package certwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpError wraps an HTTP error with status code
type httpError struct {
	StatusCode int
	Message    string
}

func (e *httpError) Error() string {
	return e.Message
}

// WebhookClient handles HTTP communication with the portal service
type WebhookClient struct {
	httpClient *http.Client
	portalURL  string
	secret     string
	timeout    time.Duration
	config     *Config
}

// NewWebhookClient creates a new webhook client
func NewWebhookClient(portalURL, secret string, timeout time.Duration) *WebhookClient {
	d := DefaultRetryCount
	return &WebhookClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		portalURL: portalURL,
		secret:    secret,
		timeout:   timeout,
		config: &Config{
			PortalURL:     portalURL,
			GatewaySecret: secret,
			Timeout:       timeout,
			RetryCount:    &d,
		},
	}
}

// NewWebhookClientWithConfig creates a new webhook client with config
func NewWebhookClientWithConfig(config *Config) *WebhookClient {
	return &WebhookClient{
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		portalURL: config.PortalURL,
		secret:    config.GatewaySecret,
		timeout:   config.Timeout,
		config:    config,
	}
}

// sendWebhook sends a webhook to the portal for the specified domain
func (c *WebhookClient) sendWebhook(ctx context.Context, domain string, status SSLStatus, errorMsg, timestamp string) error {
	url := fmt.Sprintf("%s/internal/websites/%s/ssl-status", c.portalURL, domain)

	payload := SSLStatusUpdateRequest{
		Status:    status,
		Error:     errorMsg,
		Timestamp: timestamp,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(GatewaySecretHeader, c.secret)

	resp, err := c.httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read webhook response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("webhook failed with status %d: %s", resp.StatusCode, string(body)),
		}
	}
	return nil
}
