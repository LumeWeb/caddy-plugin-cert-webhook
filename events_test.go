package certwebhook

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestExtractDomainFromClientHello(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]any
		want    string
		wantErr bool
	}{
		{
			name: "valid client_hello with ServerName",
			data: map[string]any{
				"client_hello": map[string]any{
					"ServerName": "example.com",
				},
			},
			want:    "example.com",
			wantErr: false,
		},
		{
			name: "empty ServerName",
			data: map[string]any{
				"client_hello": map[string]any{
					"ServerName": "",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty event data",
			data:    map[string]any{},
			want:    "",
			wantErr: true,
		},
		{
			name: "client_hello not a map",
			data: map[string]any{
				"client_hello": "not a map",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "ServerName not a string",
			data: map[string]any{
				"client_hello": map[string]any{
					"ServerName": 123,
				},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := caddy.Event{Data: tt.data}
			got, err := extractDomainFromClientHello(event)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractDomainFromClientHello() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractDomainFromClientHello() = %v, want %v", got, tt.want)
			}
		})
	}
}
