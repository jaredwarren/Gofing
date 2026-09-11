package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func recheckEngine(t *testing.T) (*Engine, string, network.Info) {
	t.Helper()
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.105", MAC: "BC:9E:BB:8B:49:06"},
		mdns.DeviceDetails{Hostname: "switch"}, "Nintendo Co., Ltd.", time.Now(), nil)
	eng.mu.Lock()
	eng.setOnlineLocked(eng.devices[id], false)
	eng.mu.Unlock()
	return eng, id, info
}

// A silent device present only at Layer 2 must come back online, and the result
// must say ARP is why — that is the whole point of the button.
func TestRecheckUsesARPEvidence(t *testing.T) {
	eng, id, info := recheckEngine(t)
	_ = info
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.105", MAC: "BC:9E:BB:8B:49:06", Iface: "en0",
		}}, nil
	}
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	res, err := eng.RecheckDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("RecheckDevice: %v", err)
	}
	if !res.IsOnline {
		t.Fatal("ARP-backed device should be reported online")
	}
	if res.WasOnline {
		t.Error("WasOnline should reflect the pre-check state")
	}
	if res.Evidence != "arp" {
		t.Errorf("Evidence = %q, want arp", res.Evidence)
	}
	if !res.Changed {
		t.Error("an offline->online flip is a meaningful change")
	}
	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Error("the device itself should have been brought online")
	}
}

func TestRecheckUsesProbeEvidenceWhenNoARP(t *testing.T) {
	eng, id, _ := recheckEngine(t)
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 4.5, true }

	res, err := eng.RecheckDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("RecheckDevice: %v", err)
	}
	if !res.IsOnline || res.Evidence != "probe" {
		t.Fatalf("online=%v evidence=%q, want true/probe", res.IsOnline, res.Evidence)
	}
	if res.LatencyMs != 4.5 {
		t.Errorf("LatencyMs = %v, want 4.5", res.LatencyMs)
	}
}

// A single failed check must not retire a device on its own; the debounce in
// the presence tier owns that decision.
func TestRecheckDoesNotRetireOnOneMiss(t *testing.T) {
	eng, id, _ := recheckEngine(t)
	eng.mu.Lock()
	eng.setOnlineLocked(eng.devices[id], true)
	eng.mu.Unlock()

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	res, err := eng.RecheckDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("RecheckDevice: %v", err)
	}
	if !res.IsOnline {
		t.Fatal("one failed check should not flip a device offline")
	}
	if res.Evidence != "none" {
		t.Errorf("Evidence = %q, want none", res.Evidence)
	}

	// Repeated failures do retire it, at the normal threshold.
	for i := 1; i < offlineMissThreshold; i++ {
		if _, err := eng.RecheckDevice(context.Background(), id); err != nil {
			t.Fatalf("RecheckDevice: %v", err)
		}
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatalf("device should be offline after %d failed checks", offlineMissThreshold)
	}
}

func TestRecheckFollowsDeviceToNewIP(t *testing.T) {
	eng, id, _ := recheckEngine(t)
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.150", MAC: "BC:9E:BB:8B:49:06", Iface: "en0",
		}}, nil
	}
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	res, err := eng.RecheckDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("RecheckDevice: %v", err)
	}
	if res.Device.IP != "192.168.0.150" {
		t.Fatalf("IP = %q, want the address ARP found the MAC at", res.Device.IP)
	}
}

func TestRecheckUnknownDevice(t *testing.T) {
	eng := New(nil)
	if _, err := eng.RecheckDevice(context.Background(), "nope"); err == nil {
		t.Fatal("expected an error for an unknown device")
	}
}
