package certwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.lumeweb.com/caddy-plugin-cert-webhook/internal/client"
)

// DefaultEndpoint is the default API endpoint for the IPFS portal service.
const DefaultEndpoint = "ipfs.pinner.xyz"

// validEndpoint checks if an endpoint contains only valid domain characters
func validEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	for i := 0; i < len(endpoint); i++ {
		c := endpoint[i]
		if !(c == '.' || c == '-' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// ClientOption is an option for configuring the Portal client.
type ClientOption func(*clientConfig)

type clientConfig struct {
	endpoint    string
	httpClient  *http.Client
	gatewaySecret string
}

// defaultClientConfig returns a clientConfig with sensible defaults.
func defaultClientConfig() *clientConfig {
	return &clientConfig{
		endpoint: DefaultEndpoint,
	}
}

// WithEndpoint sets the API endpoint for the client.
func WithEndpoint(endpoint string) ClientOption {
	return func(cfg *clientConfig) {
		cfg.endpoint = endpoint
	}
}

// WithHTTPClient sets the HTTP client for the client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(cfg *clientConfig) {
		cfg.httpClient = httpClient
	}
}

// WithGatewaySecret sets the gateway secret for authentication.
func WithGatewaySecret(secret string) ClientOption {
	return func(cfg *clientConfig) {
		cfg.gatewaySecret = secret
	}
}

// Client implements the IPFS portal API using the generated OpenAPI client.
type Client struct {
	client         client.ClientWithResponsesInterface
	gatewaySecret  string
}

// NewClient creates a new Portal client with the given options.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	if !validEndpoint(cfg.endpoint) {
		return nil, fmt.Errorf("invalid endpoint: %s", cfg.endpoint)
	}

	serverURL := "https://" + cfg.endpoint
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c, err := client.NewClientWithResponses(serverURL, client.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to create portal client: %w", err)
	}

	return &Client{client: c, gatewaySecret: cfg.gatewaySecret}, nil
}

// addGatewaySecret returns a RequestEditorFn that adds the X-Gateway-Secret header.
func (c *Client) addGatewaySecret() client.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-Gateway-Secret", c.gatewaySecret)
		return nil
	}
}

// GetWebsite retrieves website configuration for gateway.
func (c *Client) GetWebsite(ctx context.Context, domain string) (*client.GatewayWebsiteResponse, error) {
	resp, err := c.client.GetInternalWebsitesDomainWithResponse(ctx, domain, c.addGatewaySecret())
	if err != nil {
		return nil, err
	}
	defer resp.HTTPResponse.Body.Close()

	if resp.HTTPResponse.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.HTTPResponse)
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response")
	}
	return resp.JSON200, nil
}

// UpdateSSLStatus updates SSL certificate status for a website domain.
func (c *Client) UpdateSSLStatus(ctx context.Context, domain string, req client.SSLStatusUpdateRequest) (*client.WebsiteResponse, error) {
	resp, err := c.client.PostInternalWebsitesDomainSslStatusWithResponse(ctx, domain, req, c.addGatewaySecret())
	if err != nil {
		return nil, err
	}
	defer resp.HTTPResponse.Body.Close()

	if resp.HTTPResponse.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.HTTPResponse)
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response")
	}
	return resp.JSON200, nil
}

// GetWebsiteStatus retrieves website status information for gateway.
func (c *Client) GetWebsiteStatus(ctx context.Context, domain string) (*client.GatewayWebsiteStatusResponse, error) {
	resp, err := c.client.GetInternalWebsitesDomainStatusWithResponse(ctx, domain, c.addGatewaySecret())
	if err != nil {
		return nil, err
	}
	defer resp.HTTPResponse.Body.Close()

	if resp.HTTPResponse.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.HTTPResponse)
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response")
	}
	return resp.JSON200, nil
}

// handleErrorResponse extracts error information from HTTP responses.
func (c *Client) handleErrorResponse(resp *http.Response) error {
	var errResp client.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	return &HTTPError{StatusCode: resp.StatusCode, Message: errResp.Error}
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return e.Message
}
