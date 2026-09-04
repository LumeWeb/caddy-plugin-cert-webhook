package certwebhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	tlds  map[string]bool
	error error
	calls int
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
	return s.response, s.error
}

func websiteWithNamespace(namespace string) *ipfs.GatewayWebsiteResponse {
	// The enum type behind GatewayWebsiteResponse.Namespace is only defined
	// in the SDK's internal client package, so it cannot be named here;
	// construct the pointer through reflection instead.
	resp := &ipfs.GatewayWebsiteResponse{}
	nsField := reflect.ValueOf(resp).Elem().FieldByName("Namespace")
	nsVal := reflect.New(nsField.Type().Elem())
	nsVal.Elem().SetString(namespace)
	nsField.Set(nsVal)
	return resp
}

// newTestChecker returns a DANEChecker whose ICANN registry is a canned map
// of common TLDs, so classification never triggers a real IANA fetch.
func newTestChecker() *DANEChecker {
	c := NewDANEChecker(nil)
	c.registry = &fakeRegistry{tlds: map[string]bool{"com": true, "org": true, "net": true}}
	return c
}

func TestIsDaneDomain_HeuristicFallback(t *testing.T) {
	// Retained as the degraded fallback only; single-label names are
	// alt-root candidates, dotted names are not.
	assert.True(t, IsDaneDomain("example"))
	assert.False(t, IsDaneDomain("example.com"))
	assert.False(t, IsDaneDomain(""))
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
	// Portal unreachable: a domain under a non-ICANN TLD is still an
	// alt-root candidate (public ACME cannot issue for it).
	lookup := &stubWebsiteLookup{error: context.DeadlineExceeded}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	assert.NoError(t, err)
	assert.True(t, isDANE, "alt-root domain with portal down should fall back to DANE")
	assert.Equal(t, NamespaceHNS, ns)
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
	// answer overrides the alt-root assumption.
	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceICANN)}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "pinner.hns")

	assert.NoError(t, err)
	assert.False(t, isDANE, "portal namespace response must be honored")
	assert.Equal(t, NamespaceICANN, ns)
}

func TestDANEChecker_IsDANEDomain_SingleLabelPortalDown(t *testing.T) {
	// Preserves the pre-existing fallback: single-label domains are
	// alt-root candidates when no portal answer exists.
	lookup := &stubWebsiteLookup{error: context.DeadlineExceeded}
	c := newTestChecker()
	c.lookup = lookup

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example")

	assert.NoError(t, err)
	assert.True(t, isDANE)
	assert.Equal(t, NamespaceHNS, ns)
}

func TestDANEChecker_IsDANEDomain_RegistryUnavailable(t *testing.T) {
	// With the root-zone list unloaded, classification degrades to the
	// single-label heuristic: dotted names stay ICANN (old behavior),
	// single labels stay alt-root candidates.
	c := newTestChecker()
	c.registry = &fakeRegistry{error: context.DeadlineExceeded}

	isDANE, ns, err := c.IsDANEDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.False(t, isDANE)
	assert.Equal(t, NamespaceICANN, ns)

	isDANE, ns, err = c.IsDANEDomain(context.Background(), "example")
	assert.NoError(t, err)
	assert.True(t, isDANE)
	assert.Equal(t, NamespaceHNS, ns)
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

	lookup := &stubWebsiteLookup{response: websiteWithNamespace(NamespaceHNS)}
	c := newTestChecker()
	c.lookup = lookup

	d := &DANECertGetter{
		logger:         zap.NewNop(),
		PortalURL:      server.URL,
		GatewaySecret:  "test-secret",
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
