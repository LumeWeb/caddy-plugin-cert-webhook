package certwebhook

import (
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
)

const (
	SSLStatusReady   SSLStatus = "ready"
	SSLStatusFailed  SSLStatus = "failed"
	SSLStatusIssuing SSLStatus = "issuing"
)

type SSLStatus string

func (a *CertWebhookApp) mapEventToStatus(eventType string, data *EventData) (SSLStatus, error) {
	if data == nil {
		return "", fmt.Errorf("event data is nil for event type: %s", eventType)
	}
	if data.Error != "" {
		return SSLStatusFailed, nil
	}

	switch eventType {
	case EventCertObtained, EventCertRenewed:
		return SSLStatusReady, nil
	case EventCertExpired:
		return SSLStatusFailed, nil
	default:
		return "", fmt.Errorf("unknown event type: %s", eventType)
	}
}

type certStatusFunc func(domain string) SSLStatus

// daneReadyCert records a DANE self-signed cert that the getter has actually
// served for a domain. It is the ready signal for getter-served domains: Caddy
// deliberately keeps manager-served certs out of its own certmagic cache (which
// is what AllMatchingCertificates reads), so readiness for a DANE domain cannot
// come from that cache. State is held process-wide so the status reporter and
// the DANE getter can share it without a direct reference between modules.
type daneReadyCert struct {
	expiresAt time.Time
}

var (
	daneReadyMu    sync.RWMutex
	daneReadyCerts = make(map[string]*daneReadyCert)
)

// markDANECertServed records that a DANE self-signed cert was served for domain,
// valid until expiresAt. Called by the getter after a successful handshake cert.
// Runs off the handshake hot path (cert issue is rare), so it also prunes any
// expired entries to bound map growth.
func markDANECertServed(domain string, expiresAt time.Time) {
	daneReadyMu.Lock()
	defer daneReadyMu.Unlock()
	for d, entry := range daneReadyCerts {
		if time.Now().After(entry.expiresAt) {
			delete(daneReadyCerts, d)
		}
	}
	daneReadyCerts[domain] = &daneReadyCert{expiresAt: expiresAt}
}

// clearDANECert marks a domain as no longer DANE-served (e.g. classification
// changed). Used defensively; not on the hot path.
func clearDANECert(domain string) {
	daneReadyMu.Lock()
	defer daneReadyMu.Unlock()
	delete(daneReadyCerts, domain)
}

// daneCertIsReady reports whether the getter has a currently-valid DANE cert
// served for domain. Read-only on the handshake hot path; expired entries are
// reclaimed by markDANECertServed.
func daneCertIsReady(domain string) bool {
	daneReadyMu.RLock()
	defer daneReadyMu.RUnlock()
	entry, ok := daneReadyCerts[domain]
	return ok && time.Now().Before(entry.expiresAt)
}

// matchingCertsSafe returns AllMatchingCertificates for domain, treating a
// missing/unprovisioned certmagic cache as "no certs" rather than panicking.
// The caddytls global certCache is nil until the TLS app provisions (e.g. in
// unit tests or early startup), so the status probe must not crash on it.
func matchingCertsSafe(domain string) (certs []certmagic.Certificate) {
	defer func() {
		if recover() != nil {
			certs = nil
		}
	}()
	return caddytls.AllMatchingCertificates(domain)
}

var defaultCertStatusFn certStatusFunc = func(domain string) SSLStatus {
	// Getter-served (DANE) domains report readiness from the getter's own served
	// state, because Caddy keeps manager certs out of the certmagic cache that
	// AllMatchingCertificates reads. Fall back to that cache only for ACME-managed
	// domains.
	if daneCertIsReady(domain) {
		return SSLStatusReady
	}

	certs := matchingCertsSafe(domain)
	if len(certs) == 0 {
		return SSLStatusIssuing
	}

	now := time.Now()
	for _, cert := range certs {
		if cert.Leaf == nil {
			continue
		}
		if !cert.Expired() && now.After(cert.Leaf.NotBefore) {
			return SSLStatusReady
		}
	}

	return SSLStatusFailed
}
