package certwebhook

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/dane"
	"go.uber.org/zap"
)

// TestDefaultCertStatusFn_DANEReady verifies that a DANE-served domain reports
// ready from the getter's served-state, even though Caddy never places manager
// certs in the certmagic cache that AllMatchingCertificates reads.
func TestDefaultCertStatusFn_DANEReady(t *testing.T) {
	defer clearDANECert("lumeweb")

	// Ensure no leftover store from a prior test shadows the DANE path.
	clearDANECert("lumeweb")

	// AllMatchingCertificates returns nothing for lumeweb (manager certs are not
	// in the certmagic cache), so without the DANE registry the default function
	// would report issuing forever.
	assert.Equal(t, SSLStatusIssuing, defaultCertStatusFn("lumeweb"))

	markDANECertServed("lumeweb", time.Now().Add(time.Hour))
	assert.Equal(t, SSLStatusReady, defaultCertStatusFn("lumeweb"))
}

// TestDefaultCertStatusFn_DANEExpired verifies that once the served DANE cert
// passes its expiry, the status falls back (no over-claim of readiness).
func TestDefaultCertStatusFn_DANEExpired(t *testing.T) {
	defer clearDANECert("lumeweb")

	markDANECertServed("lumeweb", time.Now().Add(-time.Minute))
	// Domain is not in the certmagic cache and its DANE entry is expired, so it
	// must NOT report ready.
	assert.NotEqual(t, SSLStatusReady, defaultCertStatusFn("lumeweb"))
}

// TestMarkDANECertServedPrunesExpired verifies expired entries are reclaimed on
// the write path so the registry does not grow unboundedly.
func TestMarkDANECertServedPrunesExpired(t *testing.T) {
	defer clearDANECert("expired.example")
	defer clearDANECert("fresh.example")

	markDANECertServed("expired.example", time.Now().Add(-time.Minute))
	assert.False(t, daneCertIsReady("expired.example"))

	// Issuing a fresh cert for another domain prunes the expired one.
	markDANECertServed("fresh.example", time.Now().Add(time.Hour))

	daneReadyMu.RLock()
	_, stillPresent := daneReadyCerts["expired.example"]
	daneReadyMu.RUnlock()
	assert.False(t, stillPresent, "expired DANE-ready entry should be pruned on mark")
}

// TestPemFromCertKeyRoundTrip verifies the served cert's embedded private key is
// the single source of truth for renewal: extracting it and re-issuing yields the
// same SPKI (stable TLSA) with no portal round-trip.
func TestPemFromCertKeyRoundTrip(t *testing.T) {
	domain := "example"
	certPEM, keyPEM, err := GenerateSelfSignedForDANE(domain)
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)

	// Extract the key back out of the served cert.
	extracted, err := pemFromCertKey(&tlsCert)
	require.NoError(t, err)
	assert.NotEmpty(t, extracted)

	// Re-issue a fresh cert from the extracted key; the SPKI must be identical.
	domains := []string{domain, "*." + domain}
	reCert, rerr := dane.IssueCertFromKey(extracted, domains, time.Now().Add(24*time.Hour))
	require.NoError(t, rerr)

	origSPKI, err := dane.ComputeTLSAFromCert(certPEM)
	require.NoError(t, err)
	reSPKI, err := dane.ComputeTLSAFromCert(reCert)
	require.NoError(t, err)
	assert.Equal(t, origSPKI, reSPKI, "re-issuing from the cached cert key must preserve the SPKI/TLSA")
}

// TestGetCertificate_ReclassifiedNonDANE verifies that a domain with a valid
// cached DANE cert that is later classified non-DANE is not served the stale
// cert (the classification check runs before the cert-cache hit) and its ready
// record is cleared. The cached cert itself is retained so a transient flap back
// to DANE reuses it without SPKI churn.
func TestGetCertificate_ReclassifiedNonDANE(t *testing.T) {
	defer clearDANECert("lumeweb")

	fakeCert := &tls.Certificate{}
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://localhost"),
		checker:        NewDANEChecker(nil),
	}

	// A valid cached DANE cert exists and the domain was served (ready).
	d.certs["lumeweb"] = &daneCachedCert{
		tlsCert: fakeCert,
		expiry:  time.Now().Add(time.Hour),
	}
	markDANECertServed("lumeweb", time.Now().Add(time.Hour))
	// The portal now classifies the domain as non-DANE.
	d.cacheDANEStatus("lumeweb", false, NamespaceICANN)

	hello := &tls.ClientHelloInfo{ServerName: "lumeweb"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.NoError(t, err)
	assert.Nil(t, cert, "non-DANE-classified domain must not be served a DANE cert")
	assert.False(t, daneCertIsReady("lumeweb"), "ready record must be cleared after reclassification")
}

// TestGetCertificate_CachedCertReestablishesReady verifies the cached-cert fast
// path re-marks readiness after a transient non-DANE classification cleared it.
func TestGetCertificate_CachedCertReestablishesReady(t *testing.T) {
	defer clearDANECert("lumeweb")

	fakeCert := &tls.Certificate{}
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://localhost"),
		checker:        NewDANEChecker(nil),
	}

	// Valid cached DANE cert; ready was briefly cleared (e.g. a transient flapping
	// non-DANE classification), but classification is DANE again.
	d.certs["lumeweb"] = &daneCachedCert{
		tlsCert: fakeCert,
		expiry:  time.Now().Add(time.Hour),
	}
	clearDANECert("lumeweb")
	d.cacheDANEStatus("lumeweb", true, NamespaceHNS)

	hello := &tls.ClientHelloInfo{ServerName: "lumeweb"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.NoError(t, err)
	assert.Same(t, fakeCert, cert, "served from cached cert")
	assert.True(t, daneCertIsReady("lumeweb"), "cached-cert fast path must re-establish ready")
}

// TestPemFromCertKeyNil guards against a nil/empty cert (defensive path in the
// renewal double-check).
func TestPemFromCertKeyNil(t *testing.T) {
	_, err := pemFromCertKey(nil)
	assert.Error(t, err)

	_, err = pemFromCertKey(&tls.Certificate{})
	assert.Error(t, err)
}

// TestClearDANECertOnNonDANE verifies that clearing the ready record on a
// non-DANE classification stops defaultCertStatusFn from reporting ready.
func TestClearDANECertOnNonDANE(t *testing.T) {
	defer clearDANECert("lumeweb")

	markDANECertServed("lumeweb", time.Now().Add(time.Hour))
	assert.Equal(t, SSLStatusReady, defaultCertStatusFn("lumeweb"))

	clearDANECert("lumeweb")
	assert.NotEqual(t, SSLStatusReady, defaultCertStatusFn("lumeweb"))
}
