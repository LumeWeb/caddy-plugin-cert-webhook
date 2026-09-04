package certwebhook

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/dane"
	"go.uber.org/zap"
)

// TestDANECertGetter_ApplyEnvDefaults verifies the getter falls back to the
// same PORTAL_URL / GATEWAY_SECRET environment variables the webhook app uses,
// so no duplicate config is needed when registering get_certificate dane.
func TestDANECertGetter_ApplyEnvDefaults(t *testing.T) {
	t.Setenv(EnvPortalURL, "https://portal.example.com")
	t.Setenv(EnvGatewaySecret, "sekret")

	t.Run("fills empty fields from env", func(t *testing.T) {
		g := &DANECertGetter{}
		g.applyEnvDefaults()
		assert.Equal(t, "https://portal.example.com", g.PortalURL)
		assert.Equal(t, "sekret", g.GatewaySecret)
	})

	t.Run("keeps explicitly configured fields", func(t *testing.T) {
		g := &DANECertGetter{PortalURL: "https://explicit.example.com", GatewaySecret: "explicit"}
		g.applyEnvDefaults()
		assert.Equal(t, "https://explicit.example.com", g.PortalURL)
		assert.Equal(t, "explicit", g.GatewaySecret)
	})
}

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
		checker:        newTestChecker(),
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
		checker:        newTestChecker(),
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
		checker:        newTestChecker(),
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
		checker:        newTestChecker(),
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
		checker:        newTestChecker(),
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

func TestDANECertGetter_GetCertificate_ReusesPersistedKey(t *testing.T) {
	// Generate a known key; the portal returns it via GET /internal/dns/cert/{domain}.
	// The re-issued cert must be derived from that SAME key (stable SPKI), so a
	// subsequent renewal does not change the published TLSA.
	_, keyPEM, err := GenerateSelfSignedForDANE("example")
	require.NoError(t, err)

	persistedSPKI := spkiHashFromKeyPEM(t, keyPEM)

	// The test server first confirms the domain is DANE (delegation check), then
	// serves the persisted key on the GET endpoint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/dns/delegation/example":
			resp := map[string]string{"domain": "example", "namespace": NamespaceHNS, "status": "active"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/internal/dns/cert" && r.Method == http.MethodPost:
			// Push endpoint; return success.
			resp := map[string]any{"ok": true, "tlsa": "3 1 1 " + persistedSPKI, "owner_name": "_443._tcp.example."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/internal/dns/cert/example" && r.Method == http.MethodGet:
			resp := map[string]any{"ok": true, "domain": "example", "namespace": NamespaceHNS,
				"private_key_pem": keyPEM, "cert_pem": "ignored", "tlsa": "3 1 1 " + persistedSPKI}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  fmt.Sprintf("gw-%d", time.Now().UnixNano()),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        newTestChecker(),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// The issued cert's leaf SPKI must match the persisted key's, proving the key
	// (and thus TLSA) is reused rather than regenerated.
	require.NotNil(t, cert.Leaf)
	leafSPKI := dane.ComputeTLSAFromSPKI(cert.Leaf.RawSubjectPublicKeyInfo)
	assert.Equal(t, persistedSPKI, leafSPKI, "re-issued cert must reuse the persisted key (stable SPKI)")
}

func TestDANECertGetter_GetCertificate_CorruptPersistedKeyFallsBack(t *testing.T) {
	// Portal returns a corrupt/mismatched persisted key (invalid PEM). The cert
	// getter must NOT abort the handshake; it falls back to a fresh key and
	// still returns a usable cert.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/dns/delegation/example":
			resp := map[string]string{"domain": "example", "namespace": NamespaceHNS, "status": "active"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/internal/dns/cert/example" && r.Method == http.MethodGet:
			// Corrupt key material.
			resp := map[string]any{"ok": true, "domain": "example", "namespace": NamespaceHNS,
				"private_key_pem": "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----", "cert_pem": "x", "tlsa": "3 1 1 deadbeef"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  fmt.Sprintf("gw-%d", time.Now().UnixNano()),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        newTestChecker(),
	}

	hello := &tls.ClientHelloInfo{ServerName: "example"}
	cert, err := d.GetCertificate(context.Background(), hello)
	require.NoError(t, err)
	require.NotNil(t, cert, "must fall back to a fresh cert instead of failing the handshake")
	require.NotNil(t, cert.Leaf)
	assert.Contains(t, cert.Leaf.DNSNames, "example")
}

func TestDANECertGetter_GetCertificate_ConcurrentExpiryReusesKey(t *testing.T) {
	// Regression for a concurrency race: at the 24h expiry boundary, concurrent
	// renewals must all reuse the cached key (captured at singleflight-execution
	// time) and must NOT each fall back to the portal or a fresh key. Otherwise
	// SPKI/TLSA churn + handshake stalls occur.
	keyPEM, _, err := GenerateSelfSignedForDANE("example")
	require.NoError(t, err)

	// Track how many portal GetCert calls occur.
	var getCertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/dns/delegation/example":
			resp := map[string]string{"domain": "example", "namespace": NamespaceHNS, "status": "active"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/internal/dns/cert" && r.Method == http.MethodPost:
			resp := map[string]any{"ok": true, "tlsa": "3 1 1 deadbeef", "owner_name": "_443._tcp.example."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/internal/dns/cert/example" && r.Method == http.MethodGet:
			getCertCalls.Add(1)
			// Delay to widen the race window.
			time.Sleep(50 * time.Millisecond)
			resp := map[string]any{"ok": true, "domain": "example", "namespace": NamespaceHNS,
				"private_key_pem": keyPEM, "cert_pem": "ignored", "tlsa": "3 1 1 deadbeef"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Generate a valid cert pair once so we can pre-seed a cache entry with a key.
	seedCert, seedKey, err := GenerateSelfSignedForDANE("example")
	require.NoError(t, err)
	tlsSeed, err := tls.X509KeyPair([]byte(seedCert), []byte(seedKey))
	require.NoError(t, err)

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  fmt.Sprintf("gw-%d", time.Now().UnixNano()),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        newTestChecker(),
	}

	// Pre-seed an EXPIRED cache entry carrying the key, simulating a renewal that
	// is due. cacheDANEStatus so the delegation check is skipped on the hot path.
	d.cacheDANEStatus("example", true, NamespaceHNS)
	d.certs["example"] = &daneCachedCert{
		tlsCert: &tlsSeed,
		expiry:  time.Now().Add(-time.Minute), // already expired
	}

	// Fire many concurrent renewals at the expiry boundary.
	const n = 8
	var wg sync.WaitGroup
	spkis := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hello := &tls.ClientHelloInfo{ServerName: "example"}
			cert, cerr := d.GetCertificate(context.Background(), hello)
			errs[i] = cerr
			if cert != nil && cert.Leaf != nil {
				spkis[i] = dane.ComputeTLSAFromSPKI(cert.Leaf.RawSubjectPublicKeyInfo)
			}
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "call %d", i)
		require.NotEmpty(t, spkis[i], "call %d returned a cert with no leaf", i)
	}
	// All renewals must yield the same SPKI (no churn).
	first := spkis[0]
	for i := 1; i < n; i++ {
		assert.Equal(t, first, spkis[i], "concurrent renewals must not churn the SPKI/TLSA")
	}
	// The cached key is reused locally; the portal must be consulted at most once
	// (first bootstrap), not once per concurrent caller.
	assert.LessOrEqual(t, getCertCalls.Load(), int32(1), "expired entry's key should be reused locally, not re-fetched per caller")
}

// spkiHashFromKeyPEM parses a PEM-encoded private key and returns the DANE
// SPKI SHA-256 hash (TLSA 3 1 1 data) of its public key.
func spkiHashFromKeyPEM(t *testing.T, keyPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	require.NotNil(t, block, "valid key PEM expected")

	var pub any
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "expected an ECDSA key")
		pub = signer.Public()
	case "EC PRIVATE KEY": // SEC1
		key, err := x509.ParseECPrivateKey(block.Bytes)
		require.NoError(t, err)
		pub = key.Public()
	default:
		t.Fatalf("unexpected key PEM type: %s", block.Type)
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return dane.ComputeTLSAFromSPKI(spki)
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
		checker:        newTestChecker(),
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
	c := newTestChecker()
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_DANEEnabled(t *testing.T) {
	// Single-label domains are alt-root = DANE
	c := newTestChecker()
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example")

	assert.NoError(t, err)
	assert.True(t, isDANE)
	assert.Equal(t, NamespaceHNS, ns)
}

func TestDANEChecker_IsDANEDomain_ICANNRejected(t *testing.T) {
	// Multi-label domain is ICANN
	c := newTestChecker()
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.False(t, isDANE, "icann namespace should not be DANE")
	assert.Equal(t, NamespaceICANN, ns)
}
