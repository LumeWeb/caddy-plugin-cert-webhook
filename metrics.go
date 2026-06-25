package certwebhook

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricNamespace = "caddy"
	metricSubsystem = "cert_webhook"
)

var (
	metricsOnce sync.Once

	metricWebhookDeliveries *prometheus.CounterVec
	metricCertEvents        *prometheus.CounterVec
	metricThrottled         *prometheus.CounterVec
	metricTLSGetCert        *prometheus.CounterVec
)

// initMetrics registers Prometheus counters with Caddy's metrics registry.
// Caddy's metrics module bridges this registry to OTLP when `metrics { otlp }`
// is enabled, so counters are exported via the same OTEL pipeline as Caddy's
// built-in metrics.
func initMetrics(registry *prometheus.Registry) {
	metricsOnce.Do(func() {
		metricWebhookDeliveries = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "webhook_deliveries_total",
			Help:      "Total webhook deliveries to portal API.",
		}, []string{"domain", "status", "result"})

		metricCertEvents = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "cert_events_total",
			Help:      "Total certificate events processed.",
		}, []string{"event_type", "domain"})

		metricThrottled = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "throttled_total",
			Help:      "Total events throttled by dedup/throttle.",
		}, []string{"domain", "source"})

		metricTLSGetCert = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "tls_get_cert_total",
			Help:      "Total tls_get_certificate events processed.",
		}, []string{"domain", "status"})
	})

	// Re-register on the provided registry in case this is a different one
	// (e.g. during testing). Duplicate registration of the same collector
	// is a no-op per Caddy's own pattern in reverseproxy/metrics.go.
	if registry != nil {
		for _, c := range []prometheus.Collector{
			metricWebhookDeliveries, metricCertEvents,
			metricThrottled, metricTLSGetCert,
		} {
			if err := registry.Register(c); err != nil {
				var alreadyErr prometheus.AlreadyRegisteredError
				if !errors.As(err, &alreadyErr) {
					panic(err)
				}
			}
		}
	}
}

func recordWebhookDelivery(domain string, status SSLStatus, success bool) {
	if metricWebhookDeliveries == nil {
		return
	}
	result := "success"
	if !success {
		result = "failure"
	}
	metricWebhookDeliveries.WithLabelValues(domain, string(status), result).Inc()
}

func recordCertEvent(eventType string, domain string) {
	if metricCertEvents == nil {
		return
	}
	metricCertEvents.WithLabelValues(eventType, domain).Inc()
}

func recordThrottled(domain string, source string) {
	if metricThrottled == nil {
		return
	}
	metricThrottled.WithLabelValues(domain, source).Inc()
}

func recordTLSGetCert(domain string, status SSLStatus) {
	if metricTLSGetCert == nil {
		return
	}
	metricTLSGetCert.WithLabelValues(domain, string(status)).Inc()
}
