package certwebhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	ipfs "go.lumeweb.com/ipfs-sdk"
	servicemocks "go.lumeweb.com/ipfs-sdk/mocks/services"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func newTestApp(t *testing.T, mockSvc *servicemocks.MockWebsitesService, statusFn certStatusFunc) *CertWebhookApp {
	t.Helper()
	obs, _ := observer.New(zap.DebugLevel)
	logger := zap.New(obs)
	delivery := NewWebhookDelivery(mockSvc, logger)

	if statusFn == nil {
		statusFn = func(domain string) SSLStatus { return SSLStatusIssuing }
	}

	return &CertWebhookApp{
		logger:           logger,
		delivery:         delivery,
		throttle:         &throttleMap{lastSent: make(map[string]lastSentEntry), interval: 5 * time.Minute},
		throttleInterval: 5 * time.Minute,
		certStatusFn:     statusFn,
	}
}

func tlsGetCertEvent(domain string) caddy.Event {
	return caddy.Event{
		Data: map[string]any{
			"client_hello": map[string]any{
				"ServerName": domain,
			},
		},
	}
}

func expectStatus(t *testing.T, mockSvc *servicemocks.MockWebsitesService, domain string, expectedStatus SSLStatus) {
	t.Helper()
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Run(func(ctx context.Context, d string, req ipfs.SSLStatusUpdateRequest) {
		assert.Equal(t, string(expectedStatus), req.Status)
	}).Return(nil)
}

func TestHandle_TLSGetCertificate_Issuing(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, func(domain string) SSLStatus {
		return SSLStatusIssuing
	})

	expectStatus(t, mockSvc, "example.com", SSLStatusIssuing)

	err := app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()
}

func TestHandle_TLSGetCertificate_Ready(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, func(domain string) SSLStatus {
		return SSLStatusReady
	})

	expectStatus(t, mockSvc, "example.com", SSLStatusReady)

	err := app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()
}

func TestHandle_TLSGetCertificate_Failed(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, func(domain string) SSLStatus {
		return SSLStatusFailed
	})

	expectStatus(t, mockSvc, "example.com", SSLStatusFailed)

	err := app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()
}

func TestHandle_TLSGetCertificate_Throttled(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, nil)

	app.throttle.mark("example.com", SSLStatusIssuing)

	err := app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()
}

func TestHandle_TLSGetCertificate_StatusTransitionBypass(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, nil)

	app.throttle.mark("example.com", SSLStatusIssuing)

	expectStatus(t, mockSvc, "example.com", SSLStatusReady)

	ts := time.Now().Format(time.RFC3339)
	err := app.sendWebhook("example.com", SSLStatusReady, "", ts)
	assert.NoError(t, err)
	app.delivery.Wait()
}

func TestHandle_TLSGetCertificate_CertEventThrottledSameStatus(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, nil)

	expectStatus(t, mockSvc, "example.com", SSLStatusReady)

	ts := time.Now().Format(time.RFC3339)
	err := app.sendWebhook("example.com", SSLStatusReady, "", ts)
	assert.NoError(t, err)
	app.delivery.Wait()

	assert.False(t, app.shouldSend("example.com", SSLStatusReady))
}

func TestHandle_TLSGetCertificate_EmptyData(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, nil)

	event := caddy.Event{Data: map[string]any{}}
	err := app.handleTLSGetCertificateEvent(event)
	assert.NoError(t, err)
}

func TestHandle_ReadyFailedReadyRoundTrip(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, func(domain string) SSLStatus {
		return SSLStatusReady
	})

	var delivered []SSLStatus
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		mock.Anything, mock.Anything, mock.Anything,
	).Run(func(ctx context.Context, d string, req ipfs.SSLStatusUpdateRequest) {
		delivered = append(delivered, SSLStatus(req.Status))
	}).Return(nil).Times(3)

	// Step 1: ready
	err := app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()

	// Step 2: ready → failed must bypass throttle
	assert.True(t, app.shouldSend("example.com", SSLStatusFailed))
	app.certStatusFn = func(domain string) SSLStatus { return SSLStatusFailed }
	err = app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()

	// Step 3: failed → ready must bypass throttle
	assert.True(t, app.shouldSend("example.com", SSLStatusReady))
	app.certStatusFn = func(domain string) SSLStatus { return SSLStatusReady }
	err = app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	assert.NoError(t, err)
	app.delivery.Wait()

	// Step 4: same status now throttled
	assert.False(t, app.shouldSend("example.com", SSLStatusReady))

	assert.Equal(t, []SSLStatus{SSLStatusReady, SSLStatusFailed, SSLStatusReady}, delivered)
}

func TestHandle_CertEventAndTLSGetCertRace(t *testing.T) {
	mockSvc := servicemocks.NewMockWebsitesService(t)
	app := newTestApp(t, mockSvc, func(domain string) SSLStatus {
		return SSLStatusReady
	})

	var mu sync.Mutex
	var delivered []SSLStatus
	mockSvc.EXPECT().UpdateSSLStatusInternal(
		mock.Anything, mock.Anything, mock.Anything,
	).Run(func(ctx context.Context, d string, req ipfs.SSLStatusUpdateRequest) {
		mu.Lock()
		delivered = append(delivered, SSLStatus(req.Status))
		mu.Unlock()
	}).Return(nil).Times(3)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		ts := time.Now().Format(time.RFC3339)
		app.sendWebhook("example.com", SSLStatusReady, "", ts)
	}()

	go func() {
		defer wg.Done()
		ts := time.Now().Format(time.RFC3339)
		app.sendWebhook("example.com", SSLStatusFailed, "", ts)
	}()

	go func() {
		defer wg.Done()
		app.handleTLSGetCertificateEvent(tlsGetCertEvent("example.com"))
	}()

	wg.Wait()
	app.delivery.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, delivered, 3)
	// Must contain at least one ready and one failed (transition always bypasses)
	hasReady := false
	hasFailed := false
	for _, s := range delivered {
		if s == SSLStatusReady {
			hasReady = true
		}
		if s == SSLStatusFailed {
			hasFailed = true
		}
	}
	assert.True(t, hasReady, "expected at least one ready delivery")
	assert.True(t, hasFailed, "expected at least one failed delivery")
}

func TestCertStatusFn_MockedIssuing(t *testing.T) {
	called := false
	fn := func(domain string) SSLStatus {
		called = true
		return SSLStatusIssuing
	}
	result := fn("example.com")
	assert.True(t, called)
	assert.Equal(t, SSLStatusIssuing, result)
}

func TestCertStatusFn_MockedReady(t *testing.T) {
	fn := func(domain string) SSLStatus { return SSLStatusReady }
	assert.Equal(t, SSLStatusReady, fn("example.com"))
}

func TestCertStatusFn_MockedFailed(t *testing.T) {
	fn := func(domain string) SSLStatus { return SSLStatusFailed }
	assert.Equal(t, SSLStatusFailed, fn("example.com"))
}
