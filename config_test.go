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

func TestConfigIgnoredDomains_EnvFallback(t *testing.T) {
	t.Setenv(EnvIgnoredDomains, "gateway.example.com,gateway2.example.com")
	c := &Config{}
	c.Provision()
	assert.Equal(t, []string{"gateway.example.com", "gateway2.example.com"}, c.IgnoredDomains)
}

func TestConfigIgnoredDomains_EnvWithSpaces(t *testing.T) {
	t.Setenv(EnvIgnoredDomains, " gateway.example.com , gateway2.example.com ")
	c := &Config{}
	c.Provision()
	assert.Equal(t, []string{"gateway.example.com", "gateway2.example.com"}, c.IgnoredDomains)
}

func TestConfigIgnoredDomains_EnvEmpty(t *testing.T) {
	t.Setenv(EnvIgnoredDomains, "")
	c := &Config{}
	c.Provision()
	assert.Nil(t, c.IgnoredDomains)
}

func TestConfigIgnoredDomains_EnvSingleDomain(t *testing.T) {
	t.Setenv(EnvIgnoredDomains, "gateway.example.com")
	c := &Config{}
	c.Provision()
	assert.Equal(t, []string{"gateway.example.com"}, c.IgnoredDomains)
}

func TestConfigIgnoredDomains_ExplicitOverEnv(t *testing.T) {
	t.Setenv(EnvIgnoredDomains, "gateway.example.com")
	c := &Config{IgnoredDomains: []string{"custom.example.com"}}
	c.Provision()
	assert.Equal(t, []string{"custom.example.com"}, c.IgnoredDomains)
}

func TestParseDomainList_Empty(t *testing.T) {
	assert.Nil(t, parseDomainList(""))
}

func TestParseDomainList_SingleDomain(t *testing.T) {
	result := parseDomainList("gateway.example.com")
	assert.Equal(t, []string{"gateway.example.com"}, result)
}

func TestParseDomainList_MultipleDomains(t *testing.T) {
	result := parseDomainList("a.com,b.com,c.com")
	assert.Equal(t, []string{"a.com", "b.com", "c.com"}, result)
}

func TestParseDomainList_TrimsSpaces(t *testing.T) {
	result := parseDomainList(" a.com , b.com , c.com ")
	assert.Equal(t, []string{"a.com", "b.com", "c.com"}, result)
}

func TestParseDomainList_FilterEmpty(t *testing.T) {
	result := parseDomainList("a.com,,b.com,")
	assert.Equal(t, []string{"a.com", "b.com"}, result)
}
