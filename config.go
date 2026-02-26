package certwebhook

import (
	"os"
	"time"
)

const (
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second

	// DefaultRetryCount is the default number of retry attempts
	DefaultRetryCount = 5

	// GatewaySecretHeader is the header name for gateway authentication
	GatewaySecretHeader = "X-Gateway-Secret"

	// EnvGatewaySecret is the environment variable for the gateway secret
	EnvGatewaySecret = "GATEWAY_SECRET"

	// EnvPortalURL is the environment variable for the portal URL
	EnvPortalURL = "PORTAL_URL"
)

// Config holds the configuration for the webhook plugin
type Config struct {
	// PortalURL is the base URL of the portal service
	PortalURL string `json:"portal_url,omitempty"`

	// GatewaySecret is the shared secret for portal authentication
	GatewaySecret string `json:"-"`

	// Timeout is the HTTP client timeout for webhook delivery
	Timeout time.Duration `json:"timeout,omitempty"`

	// RetryCount is the number of retry attempts for transient failures
	RetryCount *int `json:"retry_count,omitempty"`
}

// Provision loads configuration from environment variables and sets defaults
func (c *Config) Provision() {
	// Load from environment variables
	if c.PortalURL == "" {
		c.PortalURL = os.Getenv(EnvPortalURL)
	}
	if c.GatewaySecret == "" {
		c.GatewaySecret = os.Getenv(EnvGatewaySecret)
	}

	// Set defaults
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.RetryCount == nil {
		d := DefaultRetryCount
		c.RetryCount = &d
	}
}

// Validate checks that required configuration is present
func (c *Config) Validate() error {
	if c.PortalURL == "" {
		return &ConfigError{Field: "portal_url", Message: "portal URL is required"}
	}
	if c.GatewaySecret == "" {
		return &ConfigError{Field: "gateway_secret", Message: "gateway secret is required"}
	}
	return nil
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
