package certwebhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestDANEManager creates a DANECertManager backed by a PortalClient
// pointing at the given test server URL.
func newTestDANEManager(t *testing.T, serverURL string) *DANECertManager {
	t.Helper()
	portal, err := NewPortalClient(serverURL, "secret")
	require.NoError(t, err)
	return NewDANECertManager(portal.DNS(), zap.NewNop())
}

func TestDANECertGetter_GetCertificate_NonDANEDomain(t *testing.T) {
	// Portal says domain is not DANE-enabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        NewDANEChecker(nil),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	cert, err := d.GetCertificate(context.Background(), hello)

	assert.Nil(t, err)
	assert.Nil(t, cert, "non-DANE domain should return nil cert")
}

func TestDANECertGetter_GetCertificate_EmptyServerName(t *testing.T) {
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://localhost"),
		checker:        NewDANEChecker(nil),
	}

	hello := &tls.ClientHelloInfo{ServerName: ""}
	cert, err := d.GetCertificate(context.Background(), hello)

	assert.Nil(t, err)
	assert.Nil(t, cert)
}

func TestDANECertGetter_GetCertificate_DANEDomain(t *testing.T) {
	// Portal says domain is DANE-enabled AND accepts cert push
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/dns/delegation/example" {
			resp := map[string]string{"domain": "example", "namespace": NamespaceHNS, "status": "active"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/internal/dns/cert" {
			resp := map[string]any{"ok": true, "tlsa": "3 1 1 abcd1234", "owner_name": "_443._tcp.example."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  "test-secret",
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        NewDANEChecker(nil),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.NoError(t, err)
	require.NotNil(t, cert, "DANE domain should return a self-signed cert")
	assert.Contains(t, cert.Leaf.DNSNames, "example")
	assert.Contains(t, cert.Leaf.DNSNames, "*.example")
}

func TestDANECertGetter_GetCertificate_CachedCert(t *testing.T) {
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://localhost"),
		checker:        NewDANEChecker(nil),
	}

	fakeCert := &tls.Certificate{}
	d.certs["example"] = &daneCachedCert{
		tlsCert: fakeCert,
		expiry:  time.Now().Add(1 * time.Hour),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)

	assert.Nil(t, err)
	assert.Same(t, fakeCert, cert, "should return cached cert")
}

func TestDANECertGetter_GetCertificate_ExpiredCacheRegenerates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/dns/delegation/example" {
			resp := map[string]string{"domain": "example", "namespace": NamespaceHNS, "status": "active"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/internal/dns/cert" {
			resp := map[string]any{"ok": true, "tlsa": "3 1 1 abcd1234", "owner_name": "_443._tcp.example."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        NewDANEChecker(nil),
	}

	d.certs["example"] = &daneCachedCert{
		tlsCert: &tls.Certificate{},
		expiry:  time.Now().Add(-1 * time.Hour),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.NoError(t, err)
	require.NotNil(t, cert, "should regenerate cert after cache expiry")
}

func TestDANECertGetter_GetCertificate_PortalUnreachable(t *testing.T) {
	// When the portal is unreachable, the cert getter still generates
	// a self-signed cert for DANE domains. The push fails async but
	// does not block the handshake.
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://127.0.0.1:1"),
		checker:        NewDANEChecker(nil),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)

	assert.Nil(t, err)
	require.NotNil(t, cert, "should still generate self-signed cert when portal is unreachable")
	assert.Contains(t, cert.Leaf.DNSNames, "example")
}

func TestDANECertGetter_CaddyModule(t *testing.T) {
	info := (&DANECertGetter{}).CaddyModule()
	assert.Equal(t, caddy.ModuleID("tls.get_certificate.dane"), info.ID)
}

func TestDANEChecker_IsDANEDomain_NotFound(t *testing.T) {
	// Multi-label domains (with dots) are ICANN, not DANE
	c := NewDANEChecker(nil)
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_DANEEnabled(t *testing.T) {
	// Single-label domains are alt-root = DANE
	c := NewDANEChecker(nil)
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example")

	assert.NoError(t, err)
	assert.True(t, isDANE)
	assert.Equal(t, NamespaceHNS, ns)
}

func TestDANEChecker_IsDANEDomain_ICANNRejected(t *testing.T) {
	// Multi-label domain is ICANN
	c := NewDANEChecker(nil)
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.False(t, isDANE, "icann namespace should not be DANE")
	assert.Equal(t, NamespaceICANN, ns)
}
