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

func TestDANECertManager_ComputeTLSA(t *testing.T) {
	portal, err := NewPortalClient("https://localhost", "secret")
	require.NoError(t, err)
	m := NewDANECertManager(portal.DNS(), zap.NewNop())

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

func TestDANECertManager_PushCert_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpE\n-----END CERTIFICATE-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/internal/dns/cert", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "test-secret", r.Header.Get("X-Gateway-Secret"))

		var req map[string]string
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "example", req["domain"])
		assert.Equal(t, NamespaceHNS, req["namespace"])
		assert.Equal(t, certPEM, req["cert_pem"])

		resp := map[string]any{"ok": true, "tlsa": "3 1 1 abc123", "owner_name": "_443._tcp.example."}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	portal, err := NewPortalClient(server.URL, "test-secret")
	require.NoError(t, err)
	m := NewDANECertManager(portal.DNS(), zap.NewNop())
	result, err := m.PushCert(context.Background(), "example", NamespaceHNS, certPEM)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Ok)
	assert.Equal(t, "3 1 1 abc123", result.Tlsa)
	assert.Equal(t, "_443._tcp.example.", result.OwnerName)
}

func TestDANECertManager_PushCert_StatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer server.Close()

	portal, err := NewPortalClient(server.URL, "secret")
	require.NoError(t, err)
	m := NewDANECertManager(portal.DNS(), zap.NewNop())
	_, err = m.PushCert(context.Background(), "example", NamespaceHNS, "cert-pem")

	assert.Error(t, err)
}

func TestDANECertManager_PushCert_ServerUnreachable(t *testing.T) {
	portal, err := NewPortalClient("http://127.0.0.1:1", "secret")
	require.NoError(t, err)
	m := NewDANECertManager(portal.DNS(), zap.NewNop())
	_, err = m.PushCert(context.Background(), "example", NamespaceHNS, "cert-pem")

	assert.Error(t, err)
}

func TestGenerateSelfSignedForDANE(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedForDANE("example")
	assert.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)
	assert.Contains(t, certPEM, "BEGIN CERTIFICATE")
}
