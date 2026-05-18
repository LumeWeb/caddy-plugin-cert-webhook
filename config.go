package certwebhook

import (
	"os"
)

const (
	GatewaySecretHeader = "X-Gateway-Secret"

	EnvGatewaySecret = "GATEWAY_SECRET"
	EnvPortalURL     = "PORTAL_URL"
)

type Config struct {
	PortalURL     string
	GatewaySecret string
}

func (c *Config) Provision() {
	if c.PortalURL == "" {
		c.PortalURL = os.Getenv(EnvPortalURL)
	}
	if c.GatewaySecret == "" {
		c.GatewaySecret = os.Getenv(EnvGatewaySecret)
	}
}

func (c *Config) Validate() error {
	if c.PortalURL == "" {
		return &ConfigError{Field: "portal_url", Message: "portal URL is required"}
	}
	if c.GatewaySecret == "" {
		return &ConfigError{Field: "gateway_secret", Message: "gateway secret is required"}
	}
	return nil
}

type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
