package certwebhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookClient_SendWebhook(t *testing.T) {
	tests := []struct {
		name           string
		server         *httptest.Server
		statusCode     int
		responseBody   string
		wantErr        bool
		wantStatusCode int
	}{
		{
			name: "successful webhook",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.URL.Path != "/internal/websites/example.com/ssl-status" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Header.Get(GatewaySecretHeader) != "test-secret" {
					t.Errorf("expected gateway secret header")
				}
				w.WriteHeader(http.StatusOK)
			})),
			statusCode:     http.StatusOK,
			responseBody:   "",
			wantErr:        false,
			wantStatusCode: http.StatusOK,
		},
		{
			name: "webhook with 404",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("not found"))
			})),
			statusCode:     http.StatusNotFound,
			responseBody:   "not found",
			wantErr:        true,
			wantStatusCode: http.StatusNotFound,
		},
		{
			name: "webhook with 500",
			server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal server error"))
			})),
			statusCode:     http.StatusInternalServerError,
			responseBody:   "internal server error",
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.server.Close()

			client := NewWebhookClientWithConfig(&Config{PortalURL: tt.server.URL, GatewaySecret: "test-secret", Timeout: 30 * time.Second, RetryCount: new(5)})
			err := client.sendWebhook(context.Background(), "example.com", SSLStatusReady, "", time.Now().Format(time.RFC3339))

			if (err != nil) != tt.wantErr {
				t.Errorf("sendWebhook() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookClient_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get(GatewaySecretHeader) != "my-secret" {
			t.Errorf("expected X-Gateway-Secret header, got %s", r.Header.Get(GatewaySecretHeader))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewWebhookClientWithConfig(&Config{PortalURL: server.URL, GatewaySecret: "my-secret", Timeout: 30 * time.Second, RetryCount: new(5)})
	err := client.sendWebhook(context.Background(), "example.com", SSLStatusReady, "", time.Now().Format(time.RFC3339))

	if err != nil {
		t.Errorf("sendWebhook() error = %v", err)
	}
}
