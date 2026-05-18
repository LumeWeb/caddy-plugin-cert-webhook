package certwebhook

import (
	"os"
	"time"
)

const (
	GatewaySecretHeader = "X-Gateway-Secret"

	EnvGatewaySecret    = "GATEWAY_SECRET"
	EnvPortalURL        = "PORTAL_URL"
	EnvThrottleInterval = "THROTTLE_INTERVAL"
)

type Config struct {
	PortalURL        string
	GatewaySecret    string
	ThrottleInterval string
}

func (c *Config) Provision() {
	if c.PortalURL == "" {
		c.PortalURL = os.Getenv(EnvPortalURL)
	}
	if c.GatewaySecret == "" {
		c.GatewaySecret = os.Getenv(EnvGatewaySecret)
	}
	if c.ThrottleInterval == "" {
		c.ThrottleInterval = os.Getenv(EnvThrottleInterval)
	}
}

func (c *Config) throttleInterval() time.Duration {
	if c.ThrottleInterval == "" {
		return defaultThrottleInterval
	}
	d, err := time.ParseDuration(c.ThrottleInterval)
	if err != nil {
		return defaultThrottleInterval
	}
	if d <= 0 {
		return defaultThrottleInterval
	}
	return d
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
