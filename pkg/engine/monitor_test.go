package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func TestMonitorMarksOfflineAfterDebouncedMisses(t *testing.T) {
	eng := New(nil)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50", LatencyMs: 1}, mdns.DeviceDetails{
		Hostname: "cam",
	}, "Unknown", time.Now(), nil)

	var probes int32
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		atomic.AddInt32(&probes, 1)
		return 0, false
	}

	eng.MonitorOnce(context.Background())
	dev, _ := eng.GetDevice(id)
	if !dev.IsOnline {
		t.Fatal("should stay online after 1 miss")
	}

	eng.MonitorOnce(context.Background())
	dev, _ = eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("should be offline after 2 consecutive misses")
	}
	if atomic.LoadInt32(&probes) < 2 {
		t.Fatalf("probes=%d", probes)
	}
}

func TestMonitorBringsDeviceOnline(t *testing.T) {
	eng := New(nil)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:51", LatencyMs: 1}, mdns.DeviceDetails{
		Hostname: "cam",
	}, "Unknown", time.Now(), nil)
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }
	eng.MonitorOnce(context.Background())
	eng.MonitorOnce(context.Background())
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

func TestMonitorSkipsWhenScanning(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:52"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	called := false
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		called = true
		return 1, true
	}
	eng.mu.Lock()
	eng.isScanning = true
	eng.mu.Unlock()
	eng.MonitorOnce(context.Background())
	if called {
		t.Fatal("must not probe during a full scan")
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
