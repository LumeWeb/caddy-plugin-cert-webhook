package certwebhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.lumeweb.com/dane"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

func init() {
	caddy.RegisterModule(&DANECertGetter{})
}

// validatePortalURL enforces HTTPS for portal URLs carrying secrets.
func validatePortalURL(portalURL string) error {
	u, err := url.Parse(strings.TrimSuffix(portalURL, "/"))
	if err != nil {
		return fmt.Errorf("invalid portal URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("portal_url must use https scheme, got: %s", u.Scheme)
	}
	return nil
}

// DANECertGetter is a Caddy module that provides self-signed certificates
// for DANE-enabled alt-root domains. It queries the
// portal to determine whether a domain needs DANE, and if so, generates a
// self-signed cert and pushes it to the portal for TLSA computation.
//
// Non-DANE domains return nil to fall through to standard ACME issuance.
// It implements certmagic.Manager and registers as tls.get_certificate.dane.
type DANECertGetter struct {
	// PortalURL is the base URL of the Pinner portal API.
	PortalURL string `json:"portal_url,omitempty"`

	// GatewaySecret is the X-Gateway-Secret header value for portal auth.
	GatewaySecret string `json:"gateway_secret,omitempty"`

	logger  *zap.Logger
	portal  *PortalClient
	pusher  *DANECertManager
	checker *DANEChecker

	mu    sync.RWMutex
	certs map[string]*daneCachedCert

	// singleflight deduplicates concurrent cert generation per domain
	sf singleflight.Group

	// daneStatusCache caches IsDANEDomain results to avoid blocking
	// every handshake on a portal round-trip
	statusMu      sync.RWMutex
	statusCache   map[string]*daneStatusEntry
	statusCacheTTL time.Duration
}

type daneCachedCert struct {
	tlsCert *tls.Certificate
	// keyPEM is the portal-persisted private key this cert was issued from.
	// It is cached alongside the cert so renewals re-issue locally without a
	// portal round-trip and keep the SPKI (TLSA) stable. Never logged/serialized.
	keyPEM string
	expiry time.Time
}

type daneStatusEntry struct {
	isDANE   bool
	namespace string
	expiresAt time.Time
}

// daneCertTTL is how long a self-signed cert is cached before regeneration.
const daneCertTTL = 24 * time.Hour

// daneStatusCacheTTLDefault is how long DANE status lookups are cached.
const daneStatusCacheTTLDefault = 5 * time.Minute

// CaddyModule returns the Caddy module information.
func (*DANECertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.dane",
		New: func() caddy.Module { return new(DANECertGetter) },
	}
}

// Provision sets up the module.
func (d *DANECertGetter) Provision(ctx caddy.Context) error {
	if err := validatePortalURL(d.PortalURL); err != nil {
		return err
	}
	d.logger = ctx.Logger(d)
	d.certs = make(map[string]*daneCachedCert)
	d.statusCache = make(map[string]*daneStatusEntry)
	d.statusCacheTTL = daneStatusCacheTTLDefault

	portal, err := NewPortalClient(d.PortalURL, d.GatewaySecret)
	if err != nil {
		return fmt.Errorf("failed to create portal client for DANE: %w", err)
	}
	d.portal = portal
	d.pusher = NewDANECertManager(portal.DNS(), d.logger)
	d.checker = NewDANEChecker(portal.Websites())

	d.logger.Info("DANE cert getter provisioned",
		zap.String("portal_url", d.PortalURL))

	return nil
}

// cachedDANEStatus returns cached DANE status if still valid.
func (d *DANECertGetter) cachedDANEStatus(domain string) (isDANE bool, namespace string, ok bool) {
	d.statusMu.RLock()
	entry, found := d.statusCache[domain]
	d.statusMu.RUnlock()
	if !found {
		return false, "", false
	}
	if time.Now().After(entry.expiresAt) {
		d.statusMu.Lock()
		delete(d.statusCache, domain)
		d.statusMu.Unlock()
		return false, "", false
	}
	return entry.isDANE, entry.namespace, true
}

// cacheDANEStatus stores DANE status with a TTL.
func (d *DANECertGetter) cacheDANEStatus(domain string, isDANE bool, namespace string) {
	d.statusMu.Lock()
	d.statusCache[domain] = &daneStatusEntry{
		isDANE:    isDANE,
		namespace: namespace,
		expiresAt: time.Now().Add(d.statusCacheTTL),
	}
	d.statusMu.Unlock()
}

// GetCertificate implements certmagic.Manager. It returns a self-signed
// certificate for DANE-enabled domains, or nil,nil to let other
// managers/issuers try.
func (d *DANECertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, nil
	}

	// Check cert cache first
	d.mu.RLock()
	cached, ok := d.certs[domain]
	d.mu.RUnlock()

	// Carried across the renewal so the key can be reused locally (no portal
	// round-trip) once the singleflight regenerates the cert.
	var cachedKeyPEM string
	if ok && time.Now().Before(cached.expiry) {
		return cached.tlsCert, nil
	}
	if ok {
		// Preserve the key before evicting the expired entry; the renewal below
		// re-issues from it to keep the SPKI (TLSA) stable.
		cachedKeyPEM = cached.keyPEM
		d.mu.Lock()
		delete(d.certs, domain)
		d.mu.Unlock()
	}

	// Check DANE status cache before hitting the portal
	isDANE, namespace, daneCached := d.cachedDANEStatus(domain)
	if !daneCached {
		// Use singleflight to deduplicate concurrent DANE status lookups
		val, err, _ := d.sf.Do("status:"+domain, func() (any, error) {
			isDANE, namespace, err := d.checker.IsDANEDomain(ctx, domain)
			if err != nil {
				return nil, err
			}
			d.cacheDANEStatus(domain, isDANE, namespace)
			return []any{isDANE, namespace}, nil
		})
		if err != nil {
			d.logger.Debug("failed to check DANE status for domain",
				zap.String("domain", domain),
				zap.Error(err))
			return nil, nil
		}
		result := val.([]any)
		isDANE = result[0].(bool)
		namespace = result[1].(string)
	}

	if !isDANE {
		return nil, nil
	}

	// Use singleflight to deduplicate concurrent cert generation per domain
	val, err, _ := d.sf.Do("cert:"+domain, func() (any, error) {
		// Double-check cert cache after acquiring singleflight (another caller may
		// have populated it). The key survives eviction via the outer cachedKeyPEM,
		// so the re-issue happens locally with no portal round-trip.
		d.mu.RLock()
		cached, ok := d.certs[domain]
		d.mu.RUnlock()
		if ok && time.Now().Before(cached.expiry) {
			return cached.tlsCert, nil
		}

		certPEM, keyPEM, reusedKey, err := d.issueCertForKey(domain, namespace, cachedKeyPEM)
		if err != nil {
			d.logger.Error("failed to obtain self-signed cert for DANE domain",
				zap.String("domain", domain),
				zap.Error(err))
			return nil, fmt.Errorf("DANE cert generation failed: %w", err)
		}

		// Push to portal for TLSA computation (async to avoid blocking handshake).
		// The portal persists the private key once; on re-issue the pushed cert is
		// derived from that same key so the SPKI (and therefore TLSA) stays stable.
		go func(dom, ns, cert string) {
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error("DANE cert push panicked",
						zap.String("domain", dom),
						zap.Any("recover", r))
				}
			}()
			pushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, pushErr := d.pusher.PushCert(pushCtx, dom, ns, cert)
			if pushErr != nil {
				d.logger.Warn("failed to push cert to portal for TLSA",
					zap.String("domain", dom),
					zap.String("reused_key", reusedKey),
					zap.Error(pushErr))
			}
		}(domain, namespace, certPEM)

		tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse generated cert: %w", err)
		}

		d.mu.Lock()
		d.certs[domain] = &daneCachedCert{
			tlsCert: &tlsCert,
			keyPEM:  keyPEM,
			expiry:  time.Now().Add(daneCertTTL),
		}
		d.mu.Unlock()

		d.logger.Info("self-signed cert generated for DANE domain",
			zap.String("domain", domain),
			zap.String("reused_key", reusedKey))

		return &tlsCert, nil
	})

	if err != nil {
		return nil, err
	}
	return val.(*tls.Certificate), nil
}

// issueCertForKey obtains a self-signed cert for a DANE domain, reusing the
// stable private key so the SPKI (and published TLSA) stays constant across
// renewals.
//
//   - cachedKeyPEM, when non-empty, is the key already held in memory from a
//     prior fetch; the cert is re-issued from it locally with no network call.
//   - Otherwise the portal-persisted key is fetched once (per process, per
//     domain). Only the very first bootstrap has no key at all, in which case a
//     fresh key is generated and the portal persists it on the next cert push.
//   - Any failure (network, corrupt/mismatched key) falls back to a freshly
//     generated key rather than aborting the TLS handshake.
func (d *DANECertGetter) issueCertForKey(domain, namespace, cachedKeyPEM string) (certPEM, keyPEM, reusedKey string, err error) {
	keyPEM = cachedKeyPEM

	if keyPEM == "" {
		// No key in memory yet: consult the portal once. Bounded so a slow or
		// unreachable portal cannot stall the handshake indefinitely.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		stored, gerr := d.pusher.GetCert(ctx, domain, namespace)
		if gerr == nil && stored != nil && stored.PrivateKeyPem != "" {
			keyPEM = stored.PrivateKeyPem
		} else if gerr != nil {
			// Portal unreachable/error: still serve a cert rather than fail the
			// handshake. A fresh key churns the SPKI, but that's preferable to a
			// failed TLS handshake; the next successful fetch re-persists.
			d.logger.Warn("failed to fetch persisted DANE key, generating fresh cert",
				zap.String("domain", domain),
				zap.Error(gerr))
		}
	}

	if keyPEM != "" {
		// Re-issue a fresh self-signed cert around the stable key, preserving the
		// SPKI so the TLSA record does not change.
		domains := []string{domain, "*." + domain}
		notAfter := time.Now().AddDate(1, 0, 0)
		cert, cerr := dane.IssueCertFromKey(keyPEM, domains, notAfter)
		if cerr == nil {
			return cert, keyPEM, "true", nil
		}
		// Corrupt/mismatched persisted key: fall back to a fresh key instead of
		// aborting the handshake.
		d.logger.Warn("failed to re-issue cert from persisted key, generating fresh",
			zap.String("domain", domain),
			zap.Error(cerr))
	}

	// Bootstrap or fallback: generate a fresh key+cert. The portal persists this
	// key on the subsequent cert push.
	freshCert, freshKey, ferr := GenerateSelfSignedForDANE(domain)
	if ferr != nil {
		return "", "", "false", fmt.Errorf("generate fresh key/cert: %w", ferr)
	}
	return freshCert, freshKey, "false", nil
}

// Cleanup closes the portal client.
func (d *DANECertGetter) Cleanup() error {
	if d.portal != nil {
		d.portal.Close()
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*DANECertGetter)(nil)
	_ caddy.CleanerUpper    = (*DANECertGetter)(nil)
	_ certmagic.Manager     = (*DANECertGetter)(nil)
	_ caddyfile.Unmarshaler = (*DANECertGetter)(nil)
)

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
// Syntax:
//
//	tls {
//	    get_certificate dane
//	}
//
// Or with configuration:
//
//	tls {
//	    get_certificate dane {
//	        portal_url https://portal.example.com
//	        gateway_secret secret123
//	    }
//	}
func (d *DANECertGetter) UnmarshalCaddyfile(disp *caddyfile.Dispenser) error {
	disp.Next() // consume module name

	for nesting := disp.Nesting(); disp.NextBlock(nesting); {
		switch disp.Val() {
		case "portal_url":
			if !disp.NextArg() {
				return disp.ArgErr()
			}
			d.PortalURL = disp.Val()
		case "gateway_secret":
			if !disp.NextArg() {
				return disp.ArgErr()
			}
			d.GatewaySecret = disp.Val()
		default:
			return disp.Errf("unrecognized subdirective: %s", disp.Val())
		}
	}
	return nil
}
