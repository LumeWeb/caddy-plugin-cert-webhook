package certwebhook

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigThrottleInterval_Default(t *testing.T) {
	c := &Config{}
	assert.Equal(t, defaultThrottleInterval, c.throttleInterval())
}

func TestConfigThrottleInterval_ValidDuration(t *testing.T) {
	c := &Config{ThrottleInterval: "10m"}
	assert.Equal(t, 10*time.Minute, c.throttleInterval())
}

func TestConfigThrottleInterval_Seconds(t *testing.T) {
	c := &Config{ThrottleInterval: "30s"}
	assert.Equal(t, 30*time.Second, c.throttleInterval())
}

func TestConfigThrottleInterval_InvalidString(t *testing.T) {
	c := &Config{ThrottleInterval: "not a duration"}
	assert.Equal(t, defaultThrottleInterval, c.throttleInterval())
}

func TestConfigThrottleInterval_Zero(t *testing.T) {
	c := &Config{ThrottleInterval: "0"}
	assert.Equal(t, defaultThrottleInterval, c.throttleInterval())
}

func TestConfigThrottleInterval_Negative(t *testing.T) {
	c := &Config{ThrottleInterval: "-5m"}
	assert.Equal(t, defaultThrottleInterval, c.throttleInterval())
}

func TestConfigThrottleInterval_EnvFallback(t *testing.T) {
	t.Setenv(EnvThrottleInterval, "15m")
	c := &Config{}
	c.Provision()
	assert.Equal(t, "15m", c.ThrottleInterval)
	assert.Equal(t, 15*time.Minute, c.throttleInterval())
}

func TestConfigThrottleInterval_ExplicitOverEnv(t *testing.T) {
	t.Setenv(EnvThrottleInterval, "15m")
	c := &Config{ThrottleInterval: "2m"}
	c.Provision()
	assert.Equal(t, "2m", c.ThrottleInterval)
	assert.Equal(t, 2*time.Minute, c.throttleInterval())
}
