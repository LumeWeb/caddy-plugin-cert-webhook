package certwebhook

import (
	"context"
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

// IsDaneDomain reports whether a domain is an alt-root candidate by the
// single-label heuristic (no dot can never resolve via standard ICANN DNS).
//
// This was the primary pre-ICANN-registry classifier and is wrong for dotted
// alt-root names like pinner.hns. It is retained only as the degraded
// fallback used by DANEChecker.IsDANEDomain when the ICANN root-zone
// registry cannot be loaded; prefer the checker in all other cases.
func IsDaneDomain(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// WebsiteLookup provides portal website lookups for DANE classification.
type WebsiteLookup interface {
	GetGatewayWebsite(ctx context.Context, domain string) (*ipfs.GatewayWebsiteResponse, error)
}

// DANEChecker determines whether a domain needs DANE TLSA support.
//
// Classification is TLD-driven rather than "contains a dot" based: a domain
// whose final label is an IANA-registered TLD (e.g. example.com) is ICANN;
// anything else — including dotted alt-root names like pinner.hns — is an
// alt-root candidate for which the portal's namespace response is the
// source of truth.
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
// A domain whose final label is a known ICANN TLD is classified ICANN
// immediately; the portal is never consulted for it. For any other domain —
// a single label, or a dotted name under an alt-root TLD such as hns — the
// portal's namespace response is authoritative, and absent a portal answer
// the domain falls back to DANE/HNS (it cannot be issued via public ACME
// anyway). If the ICANN registry itself failed to load, classification
// degrades to the single-label heuristic.
func (d *DANEChecker) IsDANEDomain(ctx context.Context, domain string) (bool, string, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return false, NamespaceICANN, nil
	}

	isICANN, err := d.registry.IsICANN(ctx, domain)
	if err != nil {
		// Registry list unavailable (e.g. IANA unreachable at startup):
		// degrade to the heuristic instead of misclassifying alt-root
		// domains as ICANN and falling through to public ACME.
		if IsDaneDomain(domain) {
			return d.classifyViaPortal(ctx, domain)
		}
		return false, NamespaceICANN, nil
	}

	if isICANN {
		return false, NamespaceICANN, nil
	}

	return d.classifyViaPortal(ctx, domain)
}

// classifyViaPortal determines namespace from the portal when available.
// The portal's namespace response is the source of truth for alt-root
// candidates; when no lookup exists or it fails, the domain is assumed to
// be an alt-root (DANE/HNS) candidate.
func (d *DANEChecker) classifyViaPortal(ctx context.Context, domain string) (bool, string, error) {
	if d.lookup != nil {
		resp, err := d.lookup.GetGatewayWebsite(ctx, domain)
		if err == nil && resp != nil && resp.Namespace != nil {
			ns := string(*resp.Namespace)
			if ns == NamespaceHNS {
				return true, NamespaceHNS, nil
			}
			return false, NamespaceICANN, nil
		}
		// Portal lookup failed or namespace not set — fall back to alt-root
	}

	return true, NamespaceHNS, nil
}
