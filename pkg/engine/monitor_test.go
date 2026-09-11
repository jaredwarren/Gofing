package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func newTestEngineWithNet() *Engine {
	eng := New(nil)
	eng.notifyFn = func(string, string) error { return nil }
	home := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&home)
	eng.netDetectFn = func() (*network.Info, error) {
		cp := home
		return &cp, nil
	}
	return eng
}

func TestPresenceMarksOfflineAfterDebouncedMisses(t *testing.T) {
	eng := newTestEngineWithNet()
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50", LatencyMs: 1}, mdns.DeviceDetails{
		Hostname: "cam",
	}, "Unknown", time.Now(), nil)

	var probes int32
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		atomic.AddInt32(&probes, 1)
		return 0, false
	}

	// Presence and discovery used to keep two thresholds against one counter.
	// There is now a single owner and a single threshold.
	for i := 0; i < offlineMissThreshold-1; i++ {
		eng.MonitorOnce(context.Background())
		dev, _ := eng.GetDevice(id)
		if !dev.IsOnline {
			t.Fatalf("went offline after %d miss(es); threshold is %d", i+1, offlineMissThreshold)
		}
	}

	eng.MonitorOnce(context.Background())
	dev, _ := eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatalf("should be offline after %d consecutive misses", offlineMissThreshold)
	}
	if got := atomic.LoadInt32(&probes); got < int32(offlineMissThreshold) {
		t.Fatalf("probes=%d, want at least %d", got, offlineMissThreshold)
	}
}

func TestPresenceBringsDeviceOnline(t *testing.T) {
	eng := newTestEngineWithNet()
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:51", LatencyMs: 1}, mdns.DeviceDetails{
		Hostname: "cam",
	}, "Unknown", time.Now(), nil)
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }
	for i := 0; i < offlineMissThreshold; i++ {
		eng.MonitorOnce(context.Background())
	}
	dev, _ := eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("expected offline")
	}

	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 4.2, true }
	eng.MonitorOnce(context.Background())
	dev, _ = eng.GetDevice(id)
	if !dev.IsOnline {
		t.Fatal("expected online after probe hit")
	}
	if dev.LatencyMs != 4.2 {
		t.Fatalf("latency=%v", dev.LatencyMs)
	}
}

// TestPresenceRunsDuringDiscovery is the inversion of the old
// TestMonitorSkipsWhenScanning. Presence deferring to a running sweep is
// exactly the bug this split exists to fix: a sweep took ~20s of every 30s, so
// online/offline detection was dead most of the time.
func TestPresenceRunsDuringDiscovery(t *testing.T) {
	eng := newTestEngineWithNet()
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:52"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	var called atomic.Bool
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		called.Store(true)
		return 1, true
	}

	// Hold the discovery gate, as a sweep in progress would.
	if !eng.discoveryGate.begin() {
		t.Fatal("discovery gate should have been free")
	}
	defer eng.discoveryGate.end(time.Now())

	eng.MonitorOnce(context.Background())
	if !called.Load() {
		t.Fatal("presence must keep probing while a discovery sweep runs")
	}
	if !eng.discoveryGate.running() {
		t.Fatal("discovery gate should still be held after presence runs")
	}
}

func TestPresenceGateIsSingleFlight(t *testing.T) {
	eng := newTestEngineWithNet()
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.60", MAC: "AA:BB:CC:DD:EE:60"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	var probes atomic.Int32
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		probes.Add(1)
		return 1, true
	}

	// A tier never overlaps itself, even though it overlaps other tiers freely.
	if !eng.presenceGate.begin() {
		t.Fatal("presence gate should have been free")
	}
	eng.MonitorOnce(context.Background())
	if probes.Load() != 0 {
		t.Fatalf("a second concurrent presence pass ran; probes=%d", probes.Load())
	}
	eng.presenceGate.end(time.Now())

	eng.MonitorOnce(context.Background())
	if probes.Load() == 0 {
		t.Fatal("presence should run once the gate is released")
	}
}

func TestFireAlertRespectsAlertsEnabled(t *testing.T) {
	eng := New(nil)
	var notified atomic.Int32
	eng.notifyFn = func(title, message string) error {
		notified.Add(1)
		return nil
	}
	var alerts atomic.Int32
	eng.RegisterEventListener(func(eventType string, data interface{}) {
		if eventType == "alert" {
			alerts.Add(1)
		}
	})

	off := false
	_, _ = eng.UpdateSettings(SettingsPatch{AlertsEnabled: &off})
	eng.fireAlert("new_device", "id", "hello")
	if alerts.Load() != 0 || notified.Load() != 0 {
		t.Fatalf("alerts=%d notified=%d", alerts.Load(), notified.Load())
	}

	on := true
	desktop := true
	_, _ = eng.UpdateSettings(SettingsPatch{AlertsEnabled: &on, NotifymacOS: &desktop})
	eng.fireAlert("new_device", "id", "hello")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if alerts.Load() == 1 && notified.Load() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if alerts.Load() != 1 {
		t.Fatalf("expected SSE alert, got %d", alerts.Load())
	}
	if notified.Load() != 1 {
		t.Fatalf("expected desktop notify, got %d", notified.Load())
	}
}

func TestNewDeviceEmitsAlert(t *testing.T) {
	eng := New(nil)
	var rules []string
	eng.RegisterEventListener(func(eventType string, data interface{}) {
		if eventType != "alert" {
			return
		}
		a := data.(Alert)
		rules = append(rules, a.Rule)
	})
	eng.notifyFn = func(string, string) error { return nil }
	eng.upsertDevice(scanner.RawDevice{IP: "10.0.0.9", MAC: "AA:BB:CC:DD:EE:99"}, mdns.DeviceDetails{
		Hostname: "phone",
	}, "Apple", time.Now(), nil)
	if len(rules) != 1 || rules[0] != "new_device" {
		t.Fatalf("rules=%v", rules)
	}
}
