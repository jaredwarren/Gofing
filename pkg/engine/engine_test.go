package engine

import (
	"testing"
)

func TestIPSorting(t *testing.T) {
	if !compareIPs("192.168.0.2", "192.168.0.10") {
		t.Errorf("expected 192.168.0.2 < 192.168.0.10")
	}
	if compareIPs("192.168.1.1", "192.168.0.254") {
		t.Errorf("expected 192.168.0.254 < 192.168.1.1")
	}
}

func TestEngineEvents(t *testing.T) {
	eng := New()
	eventCount := 0

	eng.RegisterEventListener(func(eventType string, data interface{}) {
		eventCount++
	})

	eng.emitEvent("test_event", "hello")
	if eventCount != 1 {
		t.Errorf("expected 1 event emission, got %d", eventCount)
	}
}
