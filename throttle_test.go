package certwebhook

import (
	"sync"
	"testing"
	"time"
)

func TestThrottleMap_NoPriorSend(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}

	if !tm.checkAndMark("example.com", SSLStatusReady) {
		t.Error("expected checkAndMark=true for domain with no prior send")
	}
}

func TestThrottleMap_SameStatusWithinWindow(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}
	tm.checkAndMark("example.com", SSLStatusReady)

	if tm.checkAndMark("example.com", SSLStatusReady) {
		t.Error("expected checkAndMark=false for same status within window")
	}
}

func TestThrottleMap_SameStatusAfterWindow(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}
	tm.lastSent["example.com"] = lastSentEntry{
		status: SSLStatusReady,
		time:   time.Now().Add(-6 * time.Minute),
	}

	if !tm.checkAndMark("example.com", SSLStatusReady) {
		t.Error("expected checkAndMark=true for same status after window")
	}
}

func TestThrottleMap_StatusTransitionAlwaysSends(t *testing.T) {
	transitions := []struct {
		from, to SSLStatus
	}{
		{SSLStatusIssuing, SSLStatusReady},
		{SSLStatusReady, SSLStatusFailed},
		{SSLStatusFailed, SSLStatusReady},
		{SSLStatusIssuing, SSLStatusFailed},
	}

	for _, tc := range transitions {
		tm := &throttleMap{
			lastSent: make(map[string]lastSentEntry),
			interval: 5 * time.Minute,
		}
		tm.checkAndMark("example.com", tc.from)

		if !tm.checkAndMark("example.com", tc.to) {
			t.Errorf("expected checkAndMark=true for status transition %s → %s", tc.from, tc.to)
		}
	}
}

func TestThrottleMap_DifferentDomains(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}
	tm.checkAndMark("example.com", SSLStatusReady)

	if !tm.checkAndMark("other.com", SSLStatusReady) {
		t.Error("expected checkAndMark=true for different domain")
	}
}

func TestThrottleMap_CheckAndMarkRecordsStatusAndTime(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}

	before := time.Now()
	tm.checkAndMark("example.com", SSLStatusReady)
	after := time.Now()

	entry := tm.lastSent["example.com"]
	if entry.status != SSLStatusReady {
		t.Errorf("expected status=ready, got %s", entry.status)
	}
	if entry.time.Before(before) || entry.time.After(after) {
		t.Errorf("mark timestamp %v not between %v and %v", entry.time, before, after)
	}
}

func TestThrottleMap_IssuingDoesNotBlockReady(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}
	tm.checkAndMark("example.com", SSLStatusIssuing)

	if !tm.checkAndMark("example.com", SSLStatusReady) {
		t.Error("issuing should not block ready transition")
	}
}

func TestThrottleMap_ConcurrentSafety(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 1 * time.Millisecond,
	}

	done := make(chan bool, 2)
	go func() {
		for i := 0; i < 100; i++ {
			tm.checkAndMark("example.com", SSLStatusReady)
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			tm.checkAndMark("example.com", SSLStatusIssuing)
		}
		done <- true
	}()

	<-done
	<-done
}

func TestThrottleMap_CheckAndMarkAtomicNoTOCTOU(t *testing.T) {
	tm := &throttleMap{
		lastSent: make(map[string]lastSentEntry),
		interval: 5 * time.Minute,
	}

	var wg sync.WaitGroup
	sentCount := int64(0)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tm.checkAndMark("example.com", SSLStatusReady) {
				sentCount++
			}
		}()
	}

	wg.Wait()

	if sentCount != 1 {
		t.Errorf("expected exactly 1 send with atomic checkAndMark, got %d", sentCount)
	}
}
