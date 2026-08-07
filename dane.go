package certwebhook

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.lumeweb.com/dane"
	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.uber.org/zap"
)

// DANECertManager handles TLSA cert push for DANE-enabled alt-root domains.
// It uses the portal SDK's DNSService for cert push/TLSA updates instead
// of manual HTTP calls.
type DANECertManager struct {
	dns    ipfs.DNSService
	logger *zap.Logger
}

// NewDANECertManager creates a DANE cert manager backed by the SDK's DNS service.
func NewDANECertManager(dns ipfs.DNSService, logger *zap.Logger) *DANECertManager {
	return &DANECertManager{
		dns:    dns,
		logger: logger,
	}
}

// GetCert fetches the persisted DANE certificate and private key for a domain
// from the portal. Returns (nil, nil) when the portal has no stored identity
// yet (first bootstrap). The key is long-lived: Caddy must never log it.
func (m *DANECertManager) GetCert(ctx context.Context, domain, namespace string) (*ipfs.CertGetResponse, error) {
	resp, err := m.dns.GetCert(ctx, domain, namespace)
	if err != nil {
		if errors.Is(err, ipfs.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get cert failed: %w", err)
	}

	m.logger.Info("fetched persisted DANE key/cert from portal",
		zap.String("domain", domain),
		zap.String("tlsa", resp.Tlsa))

	return resp, nil
}

// PushCert pushes a certificate and its private key to the portal via the SDK's
// DNS service. The portal computes TLSA from the cert and persists the private
// key (once) so it can re-issue around a stable SPKI and serve the DANE
// republish endpoint. Passing the key is required: without it the portal has no
// key material and `dane republish` correctly reports "no stored certificate".
func (m *DANECertManager) PushCert(ctx context.Context, domain, namespace, certPEM, privateKeyPEM string) (*ipfs.CertPushResponse, error) {
	resp, err := m.dns.PushCert(ctx, ipfs.CertPushRequest{
		Domain:        domain,
		Namespace:     namespace,
		CertPem:       certPEM,
		PrivateKeyPem: privateKeyPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("cert push failed: %w", err)
	}
	if !resp.Ok {
		return nil, fmt.Errorf("cert push refused by portal for %s", domain)
	}

	m.logger.Info("cert pushed to portal",
		zap.String("domain", domain),
		zap.String("tlsa", resp.Tlsa),
		zap.String("owner_name", resp.OwnerName))

	return resp, nil
}

// UpdateTLSA pushes a pre-computed TLSA record to the portal via the SDK.
func (m *DANECertManager) UpdateTLSA(ctx context.Context, domain, namespace, certPEM, tlsa string) (*ipfs.CertPushResponse, error) {
	resp, err := m.dns.UpdateTLSA(ctx, ipfs.TLSAUpdateRequest{
		Domain:    domain,
		Namespace: namespace,
		CertPem:   certPEM,
		Tlsa:      tlsa,
	})
	if err != nil {
		return nil, fmt.Errorf("tlsa update failed: %w", err)
	}

	m.logger.Info("tlsa updated on portal",
		zap.String("domain", domain),
		zap.String("tlsa", resp.Tlsa),
		zap.String("owner_name", resp.OwnerName))

	return resp, nil
}

// ComputeTLSA computes the TLSA record locally using the dane library.
func (m *DANECertManager) ComputeTLSA(certPEM string) (string, string, error) {
	spkiHash, err := dane.ComputeTLSAFromCert(certPEM)
	if err != nil {
		return "", "", fmt.Errorf("compute TLSA: %w", err)
	}

	// Standard DANE-EE pattern: usage=3, selector=1, matching=1
	tlsa := fmt.Sprintf("3 1 1 %s", spkiHash)
	return tlsa, spkiHash, nil
}

// GenerateSelfSignedForDANE generates a self-signed ECDSA certificate
// suitable for DANE/alt-root domains using the official dane library.
func GenerateSelfSignedForDANE(domain string) (certPEM, keyPEM string, err error) {
	certPEM, keyPEM, err = dane.GenerateSelfSignedECDSA(
		[]string{domain, "*." + domain},
		time.Now().AddDate(1, 0, 0),
	)
	return certPEM, keyPEM, err
}
