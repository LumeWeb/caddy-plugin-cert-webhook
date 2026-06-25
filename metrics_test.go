package certwebhook

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func setupTestRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	registry := prometheus.NewRegistry()
	// Reset the once so initMetrics re-creates counters on the test registry
	metricsOnce = sync.Once{}
	metricWebhookDeliveries = nil
	metricCertEvents = nil
	metricThrottled = nil
	metricTLSGetCert = nil
	initMetrics(registry)
	return registry
}

func TestMetrics_RecordWebhookDelivery(t *testing.T) {
	registry := setupTestRegistry(t)

	recordWebhookDelivery("example.com", SSLStatusReady, true)
	recordWebhookDelivery("example.com", SSLStatusReady, false)
	recordWebhookDelivery("other.com", SSLStatusFailed, true)

	expected := `
# HELP caddy_cert_webhook_webhook_deliveries_total Total webhook deliveries to portal API.
# TYPE caddy_cert_webhook_webhook_deliveries_total counter
caddy_cert_webhook_webhook_deliveries_total{domain="example.com",result="failure",status="ready"} 1
caddy_cert_webhook_webhook_deliveries_total{domain="example.com",result="success",status="ready"} 1
caddy_cert_webhook_webhook_deliveries_total{domain="other.com",result="success",status="failed"} 1
`
	err := testutil.GatherAndCompare(registry, strings.NewReader(expected), "caddy_cert_webhook_webhook_deliveries_total")
	require.NoError(t, err)
}

func TestMetrics_RecordCertEvent(t *testing.T) {
	registry := setupTestRegistry(t)

	recordCertEvent(EventCertObtained, "example.com")
	recordCertEvent(EventCertRenewed, "example.com")
	recordCertEvent(EventCertExpired, "other.com")

	expected := `
# HELP caddy_cert_webhook_cert_events_total Total certificate events processed.
# TYPE caddy_cert_webhook_cert_events_total counter
caddy_cert_webhook_cert_events_total{domain="example.com",event_type="cert_obtained"} 1
caddy_cert_webhook_cert_events_total{domain="example.com",event_type="cert_renewed"} 1
caddy_cert_webhook_cert_events_total{domain="other.com",event_type="cert_expired"} 1
`
	err := testutil.GatherAndCompare(registry, strings.NewReader(expected), "caddy_cert_webhook_cert_events_total")
	require.NoError(t, err)
}

func TestMetrics_RecordThrottled(t *testing.T) {
	registry := setupTestRegistry(t)

	recordThrottled("example.com", "cert_event")
	recordThrottled("example.com", "tls_get_cert")
	recordThrottled("other.com", "cert_event")

	expected := `
# HELP caddy_cert_webhook_throttled_total Total events throttled by dedup/throttle.
# TYPE caddy_cert_webhook_throttled_total counter
caddy_cert_webhook_throttled_total{domain="example.com",source="cert_event"} 1
caddy_cert_webhook_throttled_total{domain="example.com",source="tls_get_cert"} 1
caddy_cert_webhook_throttled_total{domain="other.com",source="cert_event"} 1
`
	err := testutil.GatherAndCompare(registry, strings.NewReader(expected), "caddy_cert_webhook_throttled_total")
	require.NoError(t, err)
}

func TestMetrics_RecordTLSGetCert(t *testing.T) {
	registry := setupTestRegistry(t)

	recordTLSGetCert("example.com", SSLStatusReady)
	recordTLSGetCert("example.com", SSLStatusFailed)

	expected := `
# HELP caddy_cert_webhook_tls_get_cert_total Total tls_get_certificate events processed.
# TYPE caddy_cert_webhook_tls_get_cert_total counter
caddy_cert_webhook_tls_get_cert_total{domain="example.com",status="failed"} 1
caddy_cert_webhook_tls_get_cert_total{domain="example.com",status="ready"} 1
`
	err := testutil.GatherAndCompare(registry, strings.NewReader(expected), "caddy_cert_webhook_tls_get_cert_total")
	require.NoError(t, err)
}

func TestMetrics_NilSafety(t *testing.T) {
	// Reset to nil to simulate un-initialized state
	metricWebhookDeliveries = nil
	metricCertEvents = nil
	metricThrottled = nil
	metricTLSGetCert = nil

	// These should not panic
	recordWebhookDelivery("example.com", SSLStatusReady, true)
	recordCertEvent(EventCertObtained, "example.com")
	recordThrottled("example.com", "cert_event")
	recordTLSGetCert("example.com", SSLStatusReady)
}

func TestTracing_StartSpan(t *testing.T) {
	initTracer()
	require.NotNil(t, tracer)

	_, span := startSpan(context.Background(), "test_span")
	require.NotNil(t, span)
	span.End()
}
