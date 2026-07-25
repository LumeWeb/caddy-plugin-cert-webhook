package certwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.lumeweb.com/dane"
	"go.uber.org/zap"
)

// HNSCertManager handles self-signed cert generation and TLSA push for HNS domains.
type HNSCertManager struct {
	portalURL     string
	gatewaySecret string
	client        *http.Client
	logger        *zap.Logger
}

// NewHNSCertManager creates an HNS cert manager.
func NewHNSCertManager(portalURL, gatewaySecret string, logger *zap.Logger) *HNSCertManager {
	return &HNSCertManager{
		portalURL:     strings.TrimSuffix(portalURL, "/"),
		gatewaySecret: gatewaySecret,
		client:        &http.Client{Timeout: 30 * time.Second},
		logger:        logger,
	}
}

// IsHNSDomain returns true for HNS domains (single-label, no dot).
func IsHNSDomain(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// PushCert sends a cert to the portal's /internal/dns/cert endpoint.
// The portal computes TLSA and returns it.
func (m *HNSCertManager) PushCert(ctx context.Context, domain, certPEM string) (*CertPushResponse, error) {
	payload := CertPushRequest{
		Domain:    domain,
		Namespace: "hns",
		CertPEM:   certPEM,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal cert push request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.portalURL+"/internal/dns/cert", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Secret", m.gatewaySecret)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert push failed: %s", resp.Status)
	}

	var result CertPushResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode cert push response: %w", err)
	}

	m.logger.Info("cert pushed to portal",
		zap.String("domain", domain),
		zap.String("tlsa", result.TLSA),
		zap.String("owner_name", result.OwnerName))

	return &result, nil
}

// ComputeTLSA computes the TLSA record locally using the dane library.
func (m *HNSCertManager) ComputeTLSA(certPEM string) (string, string, error) {
	spkiHash, err := dane.ComputeTLSAFromCert(certPEM)
	if err != nil {
		return "", "", fmt.Errorf("compute TLSA: %w", err)
	}

	// Standard DANE-EE pattern: usage=3, selector=1, matching=1
	tlsa := fmt.Sprintf("3 1 1 %s", spkiHash)
	return tlsa, spkiHash, nil
}

// CertPushRequest matches the portal's /internal/dns/cert endpoint.
type CertPushRequest struct {
	Domain    string `json:"domain"`
	Namespace string `json:"namespace"`
	CertPEM   string `json:"cert_pem"`
}

// CertPushResponse matches the portal's /internal/dns/cert response.
type CertPushResponse struct {
	OK        bool   `json:"ok"`
	TLSA      string `json:"tlsa"`
	OwnerName string `json:"owner_name"`
}
