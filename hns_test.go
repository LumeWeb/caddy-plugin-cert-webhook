package certwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/dane"
	"go.uber.org/zap"
)

func TestIsHNSDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"single label", "example", true},
		{"single label unicode", "münchen", true},
		{"dot in domain", "example.com", false},
		{"subdomain", "sub.example.com", false},
		{"empty", "", false},
		{"dot only", ".", false},
		{"single char", "a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHNSDomain(tt.domain)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHNSCertManager_ComputeTLSA(t *testing.T) {
	m := NewHNSCertManager("http://localhost", "secret", zap.NewNop())

	// Generate a test cert using the dane library
	certPEM, _, err := dane.GenerateSelfSignedECDSA([]string{"test.example"}, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Skipf("could not generate test cert: %v", err)
	}

	tlsa, spkiHash, err := m.ComputeTLSA(certPEM)
	assert.NoError(t, err)
	assert.NotEmpty(t, tlsa)
	assert.NotEmpty(t, spkiHash)
	assert.Contains(t, tlsa, "3 1 1")
	assert.Contains(t, tlsa, spkiHash)
}

func TestHNSCertManager_PushCert_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpE\n-----END CERTIFICATE-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/internal/dns/cert", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "test-secret", r.Header.Get("X-Gateway-Secret"))

		var req CertPushRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "example", req.Domain)
		assert.Equal(t, "hns", req.Namespace)
		assert.Equal(t, certPEM, req.CertPEM)

		resp := CertPushResponse{OK: true, TLSA: "3 1 1 abc123", OwnerName: "_443._tcp.example."}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	m := NewHNSCertManager(server.URL, "test-secret", zap.NewNop())
	result, err := m.PushCert(context.Background(), "example", certPEM)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.OK)
	assert.Equal(t, "3 1 1 abc123", result.TLSA)
	assert.Equal(t, "_443._tcp.example.", result.OwnerName)
}

func TestHNSCertManager_PushCert_StatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer server.Close()

	m := NewHNSCertManager(server.URL, "secret", zap.NewNop())
	_, err := m.PushCert(context.Background(), "example", "cert-pem")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cert push failed")
}

func TestHNSCertManager_PushCert_ServerUnreachable(t *testing.T) {
	m := NewHNSCertManager("http://127.0.0.1:1", "secret", zap.NewNop())
	_, err := m.PushCert(context.Background(), "example", "cert-pem")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post cert")
}
