package certwebhook

import (
	"testing"
)

func TestMapEventToStatus(t *testing.T) {
	handler := &CertWebhookApp{}

	tests := []struct {
		name      string
		eventType string
		data      *EventData
		want      SSLStatus
		wantErr   bool
	}{
		{
			name:      "cert_obtained without error",
			eventType: EventCertObtained,
			data: &EventData{
				EventType: EventCertObtained,
				Domain:    "example.com",
				Error:     "",
			},
			want:    SSLStatusReady,
			wantErr: false,
		},
		{
			name:      "cert_obtained with error",
			eventType: EventCertObtained,
			data: &EventData{
				EventType: EventCertObtained,
				Domain:    "example.com",
				Error:     "ACME validation failed",
			},
			want:    SSLStatusFailed,
			wantErr: false,
		},
		{
			name:      "cert_renewed without error",
			eventType: EventCertRenewed,
			data: &EventData{
				EventType: EventCertRenewed,
				Domain:    "example.com",
				Error:     "",
			},
			want:    SSLStatusReady,
			wantErr: false,
		},
		{
			name:      "cert_renewed with error",
			eventType: EventCertRenewed,
			data: &EventData{
				EventType: EventCertRenewed,
				Domain:    "example.com",
				Error:     "Renewal timeout",
			},
			want:    SSLStatusFailed,
			wantErr: false,
		},
		{
			name:      "cert_expired",
			eventType: EventCertExpired,
			data: &EventData{
				EventType: EventCertExpired,
				Domain:    "example.com",
				Error:     "",
			},
			want:    SSLStatusFailed,
			wantErr: false,
		},
		{
			name:      "unknown event type",
			eventType: "unknown_event",
			data: &EventData{
				EventType: "unknown_event",
				Domain:    "example.com",
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handler.mapEventToStatus(tt.eventType, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapEventToStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mapEventToStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSLStatusString(t *testing.T) {
	tests := []struct {
		status SSLStatus
		want   string
	}{
		{SSLStatusReady, "ready"},
		{SSLStatusFailed, "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := string(tt.status); got != tt.want {
				t.Errorf("SSLStatus = %v, want %v", got, tt.want)
			}
		})
	}
}
