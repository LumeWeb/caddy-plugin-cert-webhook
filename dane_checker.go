package certwebhook

import (
	"context"
	"fmt"
	"strings"

	icann "go.lumeweb.com/icann-tlds"
	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.uber.org/zap"
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

// NormalizeDomain normalizes a certificate name for classification: trims
// surrounding space and the optional trailing root dot, lower-cases it, and
// reports whether anything is left.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// WebsiteLookup provides portal website lookups for DANE classification.
type WebsiteLookup interface {
	GetGatewayWebsite(ctx context.Context, domain string) (*ipfs.GatewayWebsiteResponse, error)
}

// DaneChecker is the classification surface DANECertGetter depends on.
type DaneChecker interface {
	// IsDANEDomain reports whether a domain requires DANE TLSA support
	// and which namespace it belongs to.
	IsDANEDomain(ctx context.Context, domain string) (bool, string, error)
}

// DANEChecker determines whether a domain needs DANE TLSA support.
//
// The portal's namespace response is the sole classification authority: no
// structural property of the name (label count, suffix shape) ever marks a
// domain as DANE. The ICANN root-zone registry is used only as a fast path
// to skip the portal for domains whose final label is a registered ICANN
// TLD — such a name can never be alt-root.
type DANEChecker struct {
	lookup   WebsiteLookup
	registry icann.Registry
}

// NewDANEChecker creates a DANE domain checker with the given portal lookup.
// The ICANN root-zone registry is created with defaults and fetched lazily
// on first classification.
func NewDANEChecker(lookup WebsiteLookup) *DANEChecker {
	reg, err := icann.New(icann.WithLogger(zap.NewNop()))
	if err != nil {
		// icann.New only fails on invalid options; defaults are valid.
		// This branch is unreachable but keeps the checker usable.
		reg, _ = icann.New()
	}
	return &DANEChecker{lookup: lookup, registry: reg}
}

// IsDANEDomain checks whether a domain is DANE-enabled.
//
// A domain whose final label is a registered ICANN TLD is classified ICANN
// immediately; the portal is never consulted for it. For every other
// domain — dotted alt-root names like pinner.hns and single labels alike —
// the portal must answer with a namespace. When the portal is unreachable
// or the registry cannot load, classification fails with an error instead
// of guessing, so callers can fail the handshake rather than either serve
// DANE blindly or fall through to public ACME.
func (d *DANEChecker) IsDANEDomain(ctx context.Context, domain string) (bool, string, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return false, NamespaceICANN, nil
	}

	isICANN, regErr := d.registry.IsICANN(ctx, domain)
	if regErr == nil && isICANN {
		return false, NamespaceICANN, nil
	}

	if d.lookup != nil {
		resp, lookupErr := d.lookup.GetGatewayWebsite(ctx, domain)
		if lookupErr != nil {
			return false, NamespaceICANN, fmt.Errorf("classify %s: portal lookup failed: %w", domain, lookupErr)
		}
		if resp == nil {
			return false, NamespaceICANN, fmt.Errorf("classify %s: portal returned no website data", domain)
		}
		if resp.Namespace != nil && string(*resp.Namespace) == NamespaceHNS {
			return true, NamespaceHNS, nil
		}
		return false, NamespaceICANN, nil
	}

	if regErr != nil {
		return false, NamespaceICANN, fmt.Errorf(
			"classify %s: portal lookup unavailable and icann registry failed to load: %w", domain, regErr)
	}
	return false, NamespaceICANN, fmt.Errorf(
		"classify %s: portal lookup unavailable and %s is not a registered icann tld", domain, domain)
}
