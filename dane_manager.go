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
	expiry  time.Time
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
	if ok && time.Now().Before(cached.expiry) {
		return cached.tlsCert, nil
	}
	if ok {
		// Evict expired entry
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
		// Double-check cert cache after acquiring singleflight
		d.mu.RLock()
		cached, ok := d.certs[domain]
		d.mu.RUnlock()
		if ok && time.Now().Before(cached.expiry) {
			return cached.tlsCert, nil
		}

		certPEM, keyPEM, err := GenerateSelfSignedForDANE(domain)
		if err != nil {
			d.logger.Error("failed to generate self-signed cert for DANE domain",
				zap.String("domain", domain),
				zap.Error(err))
			return nil, fmt.Errorf("DANE cert generation failed: %w", err)
		}

		// Push to portal for TLSA computation (async to avoid blocking handshake)
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
			expiry:  time.Now().Add(daneCertTTL),
		}
		d.mu.Unlock()

		d.logger.Info("self-signed cert generated for DANE domain",
			zap.String("domain", domain))

		return &tlsCert, nil
	})

	if err != nil {
		return nil, err
	}
	return val.(*tls.Certificate), nil
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
