package certwebhook

import (
	"context"
	"strings"

	ipfs "go.lumeweb.com/ipfs-sdk"
)

// Namespace constants for DANE domain classification.
const (
	// NamespaceICANN is the standard DNS namespace. Domains in this
	// namespace use normal ACME issuance and do not need DANE.
	NamespaceICANN = "icann"

	// NamespaceHNS is the Handshake namespace. These domains require
	// DANE TLSA authentication.
	NamespaceHNS = "hns"
)

// IsDaneDomain checks whether a domain is a DANE-enabled alt-root domain.
// A domain is DANE-enabled if it is a single-label domain (no dot),
// meaning it cannot be resolved via standard ICANN DNS and requires
// an alt-root delegation with DANE TLSA authentication.
func IsDaneDomain(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// WebsiteLookup provides portal website lookups for DANE classification.
type WebsiteLookup interface {
	GetGatewayWebsite(ctx context.Context, domain string) (*ipfs.GatewayWebsiteResponse, error)
}

// DANEChecker determines whether a domain needs DANE TLSA support.
// If a WebsiteLookup is available it uses the portal's namespace field;
// otherwise it falls back to the single-label heuristic.
type DANEChecker struct {
	lookup WebsiteLookup
}

// NewDANEChecker creates a DANE domain checker with the given portal lookup.
func NewDANEChecker(lookup WebsiteLookup) *DANEChecker {
	return &DANEChecker{lookup: lookup}
}

// IsDANEDomain checks whether a domain is DANE-enabled.
// Multi-label ICANN domains (containing a dot) are never DANE, so the
// portal lookup is skipped entirely for them. For single-label domains
// the portal's namespace field is consulted; if that fails, the
// single-label heuristic is used as fallback.
func (d *DANEChecker) IsDANEDomain(ctx context.Context, domain string) (bool, string, error) {
	if !IsDaneDomain(domain) {
		return false, NamespaceICANN, nil
	}

	if d.lookup != nil {
		resp, err := d.lookup.GetGatewayWebsite(ctx, domain)
		if err == nil && resp != nil && resp.Namespace != nil {
			ns := string(*resp.Namespace)
			if ns == NamespaceHNS {
				return true, NamespaceHNS, nil
			}
			return false, NamespaceICANN, nil
		}
		// Portal lookup failed or namespace not set — fall back to heuristic
	}

	return true, NamespaceHNS, nil
}
