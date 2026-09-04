package certwebhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.uber.org/zap"
)

// fakeRegistry is a canned icann.Registry implementation so tests never hit
// the network to fetch the IANA root-zone list.
type fakeRegistry struct {
	tlds         map[string]bool
	error        error
	calls        int
	refreshCalls int
}

func (f *fakeRegistry) IsICANN(ctx context.Context, domain string) (bool, error) {
	f.calls++
	if f.error != nil {
		return false, f.error
	}
	domain = NormalizeDomain(domain)
	idx := strings.LastIndex(domain, ".")
	if idx < 0 {
		return false, nil
	}
	return f.tlds[domain[idx+1:]], nil
}

func (f *fakeRegistry) IsICANNTld(ctx context.Context, tld string) (bool, error) {
	f.calls++
	if f.error != nil {
		return false, f.error
	}
	return f.tlds[NormalizeDomain(tld)], nil
}

func (f *fakeRegistry) TLDs(ctx context.Context) ([]string, error) {
	if f.error != nil {
		return nil, f.error
	}
	tlds := make([]string, 0, len(f.tlds))
	for tld := range f.tlds {
		tlds = append(tlds, tld)
	}
	return tlds, nil
}

func (f *fakeRegistry) Refresh(ctx context.Context) error {
	f.refreshCalls++
	return f.error
}

func (f *fakeRegistry) LastUpdated() (time.Time, bool) {
	return time.Time{}, false
}

func (f *fakeRegistry) Source() string {
	return "fake://tlds"
}

// stubWebsiteLookup is a canned portal WebsiteLookup for checker tests.
type stubWebsiteLookup struct {
	response *ipfs.GatewayWebsiteResponse
	error    error
	calls    int
}

func (s *stubWebsiteLookup) GetGatewayWebsite(ctx context.Context, domain string) (*ipfs.GatewayWebsiteResponse, error) {
	s.calls++
	if s.error != nil {
		return s.response, s.error
	}
	// Respect cancellation so context-handling regressions are observable.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.response, nil
}

// websiteWithNamespace builds a canned portal response for a namespace.
// The enum type behind GatewayWebsiteResponse.Namespace is only defined
// in the SDK's internal client package, so it cannot be named here;
// construct the pointer through reflection instead.
func websiteWithNamespace(namespace string) *ipfs.GatewayWebsiteResponse {
	resp := &ipfs.GatewayWebsiteResponse{}
	nsField := reflect.ValueOf(resp).Elem().FieldByName("Namespace")
	nsVal := reflect.New(nsField.Type().Elem())
	nsVal.Elem().SetString(namespace)
	nsField.Set(nsVal)
	return resp
}

// stubDANEChecker is a fully canned DaneChecker for manager-level tests
// that need to force a classification failure.
type stubDANEChecker struct {
	response bool
	err      error
}

func (s *stubDANEChecker) IsDANEDomain(ctx context.Context, domain string) (bool, string, error) {
	if s.err != nil {
		return false, NamespaceICANN, s.err
	}
	return s.response, NamespaceHNS, nil
}

// newTestChecker returns a DANEChecker whose ICANN registry is a canned map
// of common TLDs and whose portal lookup always answers with the HNS
// namespace, so classification never triggers a real IANA fetch or a real
// portal call. Tests that need a failing lookup build their own checker.
func newTestChecker() *DANEChecker {
	c := NewDANEChecker(nil)
	c.registry = &fakeRegistry{tlds: map[string]bool{"com": true, "org": true, "net": true}}
	c.lookup = &stubWebsiteLookup{response: websiteWithNamespace(NamespaceHNS)}
	return c
}

func TestDANEChecker_IsDANEDomain_EmptyDomain(t *testing.T) {
	c := newTestChecker()
	isDANE, ns, err := c.IsDANEDomain(context.Background(), "")
	assert.NoError(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_DottedHNSViaPortal(t *testing.T) {
	// Regression: pinner.hns contains a dot but is an alt-root domain.
	// The portal's namespace response must be consulted and honored.
	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceHNS)}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	assert.NoError(t, err)
	assert.True(t, isDANE, "dotted HNS domain must classify as DANE")
	assert.Equal(t, NamespaceHNS, ns)
	assert.Equal(t, 1, lookup.calls, "portal must be consulted for alt-root TLDs")
}

func TestDANEChecker_IsDANEDomain_DottedHNSPortalDown(t *testing.T) {
	// Portal unreachable for a non-ICANN-TLD name: classification must
	// fail rather than guess (there is no valid structural shortcut).
	lookup := &stubWebsiteLookup{error: context.DeadlineExceeded}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	require.Error(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
	assert.Contains(t, err.Error(), "portal lookup failed")
}

func TestDANEChecker_IsDANEDomain_ICANNTLDSkipsPortal(t *testing.T) {
	// A real ICANN TLD can never be alt-root, so the portal must not be
	// called for it (hot-path latency).
	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceHNS)}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
	assert.Equal(t, 0, lookup.calls, "portal must not be consulted for ICANN TLDs")
}

func TestDANEChecker_IsDANEDomain_PortalNamespaceIsSourceOfTruth(t *testing.T) {
	// The portal may report a non-HNS namespace for an alt-root TLD; its
	// answer overrides any alt-root assumption.
	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceICANN)}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	assert.NoError(t, err)
	assert.False(t, isDANE, "portal namespace response must be honored")
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_SingleLabelWithPortal(t *testing.T) {
	// Single labels carry no structural meaning; only the portal decides.
	c := newTestChecker()

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example")

	assert.NoError(t, err)
	assert.True(t, isDANE)
	assert.Equal(t, NamespaceHNS, ns)
}

func TestDANEChecker_IsDANEDomain_RegistryUnavailableWithPortal(t *testing.T) {
	// With the root-zone list unloaded the portal is the only authority;
	// its namespace answer still classifies the domain.
	c := newTestChecker()
	c.registry = &fakeRegistry{error: context.DeadlineExceeded}

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	assert.NoError(t, err)
	assert.True(t, isDANE, "portal namespace must be honored when the registry is unavailable")
	assert.Equal(t, NamespaceHNS, ns)
}

func TestDANEChecker_IsDANEDomain_RegistryAndPortalUnavailable(t *testing.T) {
	// Both sources down: classification must fail, not guess.
	c := newTestChecker()
	c.registry = &fakeRegistry{error: context.DeadlineExceeded}
	c.lookup = &stubWebsiteLookup{error: context.DeadlineExceeded}

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_NoLookupAndUnknownTLD(t *testing.T) {
	// No portal configured and a non-ICANN TLD: unclassifiable.
	c := newTestChecker()
	c.lookup = nil

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	require.Error(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_CaseAndTrailingDot(t *testing.T) {
	c := newTestChecker()

	isDANE, _, err := c.IsDANEDomain(context.Background(), "EXAMPLE.COM.")
	assert.NoError(t, err)
	assert.False(t, isDANE)

	isDANE, _, err = c.IsDANEDomain(context.Background(), "PINNER.HNS.")
	assert.NoError(t, err)
	assert.True(t, isDANE, "case and trailing dot must not break alt-root classification")
}

// TestDANECertGetter_GetCertificate_StatusCheckErrorFailsHandshake verifies
// the ACME fallthrough hardening: when classification fails for a domain,
// the getter returns an error so certmagic aborts the handshake instead of
// falling through to on-demand ACME, which public CAs reject for alt-root
// names.
func TestDANECertGetter_GetCertificate_StatusCheckErrorFailsHandshake(t *testing.T) {
	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://127.0.0.1:1"),
		checker:        &stubDANEChecker{err: errors.New("portal unreachable")},
	}

	hello := &tls.ClientHelloInfo{ServerName: "pinner.hns"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.Error(t, err, "classification failure must fail the handshake, not fall through to ACME")
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "DANE status check failed")
}

// TestRefreshCheckerRegistry_PeriodicRefresh verifies the background
// refresher keeps re-fetching the root-zone list so newly delegated ICANN
// TLDs are adopted without a restart.
func TestRefreshCheckerRegistry_PeriodicRefresh(t *testing.T) {
	reg := &fakeRegistry{tlds: map[string]bool{"com": true}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	refreshCheckerRegistry(ctx, reg, 20*time.Millisecond)

	assert.GreaterOrEqual(t, reg.refreshCalls, 2, "refresher should tick repeatedly until cancelled")
}

// TestDANECertGetter_GetCertificate_CancelledHandshakeContext verifies the
// singleflight context isolation: one handshake's cancelled request context
// must not poison the deduplicated status lookup for concurrent waiters —
// the lookup runs on a detached context, so classification still succeeds.
func TestDANECertGetter_GetCertificate_CancelledHandshakeContext(t *testing.T) {
	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceHNS)}
	c := newTestChecker()
	c.lookup = lookup

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, "http://127.0.0.1:1"),
		checker:        c,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hello := &tls.ClientHelloInfo{ServerName: "pinner.hns"}
	cert, err := d.GetCertificate(ctx, hello)

	require.NoError(t, err, "cancelled handshake context must not fail the shared status lookup")
	require.NotNil(t, cert)

	// Waiters sharing the singleflight result must also succeed.
	cert2, err := d.GetCertificate(context.Background(), hello)
	require.NoError(t, err)
	require.NotNil(t, cert2)
}

// TestDANECertGetter_GetCertificate_DottedHNSDomain is the full-stack
// regression: a dotted Handshake domain is served a DANE cert instead of
// falling through to ACME (which rejects .hns as not a public suffix).
func TestDANECertGetter_GetCertificate_DottedHNSDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/dns/cert":
			resp := map[string]any{"ok": true, "tlsa": "3 1 1 abcd1234", "owner_name": "_443._tcp.pinner.hns."}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		case "/allowed":
			resp := map[string]any{"ok": true}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := newTestChecker()

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  os.Getenv("CERTWEBHOOK_GATEWAY_SECRET"),
		certs:          make(map[string]*daneCachedCert),
		statusCache:    make(map[string]*daneStatusEntry),
		statusCacheTTL: daneStatusCacheTTLDefault,
		pusher:         newTestDANEManager(t, server.URL),
		checker:        c,
	}

	hello := &tls.ClientHelloInfo{ServerName: "pinner.hns"}
	cert, err := d.GetCertificate(context.Background(), hello)

	require.NoError(t, err)
	require.NotNil(t, cert, "dotted HNS domain must get a DANE cert, not nil")
	assert.Contains(t, cert.Leaf.DNSNames, "pinner.hns")
}
