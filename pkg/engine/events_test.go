package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/ports"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func TestLatencyDrifted(t *testing.T) {
	tests := []struct {
		name string
		a, b float64
		want bool
	}{
		{"identical", 3.2, 3.2, false},
		{"sub-millisecond jitter", 3.2, 3.4, false},
		{"a few ms on a fast link is still jitter", 2.0, 6.0, false},
		{"small absolute change on a slow link", 200, 204, false},
		{"proportionally small on a slow link", 200, 210, false},
		{"large relative jump", 2.0, 40.0, true},
		{"large absolute jump", 20.0, 400.0, true},
		{"dropped to zero", 50.0, 0, true},
		{"came from zero", 0, 50.0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := latencyDrifted(tc.a, tc.b); got != tc.want {
				t.Fatalf("latencyDrifted(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// The predicate must be symmetric.
			if got := latencyDrifted(tc.b, tc.a); got != tc.want {
				t.Fatalf("not symmetric: latencyDrifted(%v, %v) = %v, want %v",
					tc.b, tc.a, got, tc.want)
			}
		})
	}
}

func TestDeviceChangedMeaningfully(t *testing.T) {
	base := Device{
		ID: "x", IP: "192.168.0.5", MAC: "AA:BB:CC:DD:EE:05",
		Hostname: "pi", NameSource: mdns.NameSourceDNS, DeviceType: "Computer",
		Vendor: "Acme", Icon: "laptop", Model: "Pi 4",
		Services: []string{"SSH", "HTTP"},
		IsOnline: true, LatencyMs: 3.0,
		FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now().Add(-time.Minute),
	}

	mutate := func(f func(*Device)) Device {
		d := base
		d.Services = append([]string(nil), base.Services...)
		f(&d)
		return d
	}

	t.Run("ignored churn", func(t *testing.T) {
		for name, after := range map[string]Device{
			"LastSeen bump":    mutate(func(d *Device) { d.LastSeen = time.Now() }),
			"latency jitter":   mutate(func(d *Device) { d.LatencyMs = 3.2 }),
			"enrich timestamp": mutate(func(d *Device) { d.LastEnrichedAt = time.Now() }),
			"enrich failures":  mutate(func(d *Device) { d.EnrichFailures = 3 }),
			"identical":        mutate(func(d *Device) {}),
		} {
			if deviceChangedMeaningfully(base, after) {
				t.Errorf("%s should not push an SSE frame", name)
			}
		}
	})

	t.Run("reported changes", func(t *testing.T) {
		for name, after := range map[string]Device{
			"went offline":  mutate(func(d *Device) { d.IsOnline = false }),
			"new IP":        mutate(func(d *Device) { d.IP = "192.168.0.6" }),
			"new MAC":       mutate(func(d *Device) { d.MAC = "AA:BB:CC:DD:EE:06" }),
			"renamed":       mutate(func(d *Device) { d.Hostname = "pi-two" }),
			"name source":   mutate(func(d *Device) { d.NameSource = mdns.NameSourceARP }),
			"custom name":   mutate(func(d *Device) { d.CustomName = "Kitchen Pi" }),
			"note":          mutate(func(d *Device) { d.Note = "in the closet" }),
			"type":          mutate(func(d *Device) { d.DeviceType = "Server" }),
			"type override": mutate(func(d *Device) { d.DeviceTypeOverride = "NAS" }),
			"icon":          mutate(func(d *Device) { d.Icon = "server" }),
			"model":         mutate(func(d *Device) { d.Model = "Pi 5" }),
			"vendor":        mutate(func(d *Device) { d.Vendor = "Raspberry Pi Ltd" }),
			"private MAC":   mutate(func(d *Device) { d.IsPrivateMAC = true }),
			"risk score":    mutate(func(d *Device) { d.RiskScore = "high" }),
			"services":      mutate(func(d *Device) { d.Services = []string{"SSH"} }),
			"risk findings": mutate(func(d *Device) { d.RiskFindings = []string{"telnet open"} }),
			"previous MACs": mutate(func(d *Device) { d.PreviousMACs = []string{"AA:BB:CC:DD:EE:99"} }),
			"open ports": mutate(func(d *Device) {
				d.OpenPorts = []ports.ServicePort{{Port: 22, Name: "SSH"}}
			}),
			"latency spike": mutate(func(d *Device) { d.LatencyMs = 300 }),
		} {
			if !deviceChangedMeaningfully(base, after) {
				t.Errorf("%s should push an SSE frame", name)
			}
		}
	})
}

func TestPresenceSuppressesLatencyJitter(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.31", MAC: "AA:BB:CC:DD:EE:31", LatencyMs: 3.0},
		mdns.DeviceDetails{Hostname: "pi"}, "Acme", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	// Settle the device online first.
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 3.0, true }
	eng.PresenceOnce(context.Background(), &info)

	var updates int
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "device_updated" {
			updates++
		}
	})

	// Several passes of an unchanging, already-online device. Before the gate
	// this pushed one frame per device per pass.
	for i := 0; i < 5; i++ {
		lat := 3.0 + float64(i)*0.1
		eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return lat, true }
		eng.PresenceOnce(context.Background(), &info)
	}
	if updates != 0 {
		t.Fatalf("emitted %d frames across 5 quiet presence passes; want 0", updates)
	}
}

func TestPresenceEmitsOnOnlineFlip(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.32", MAC: "AA:BB:CC:DD:EE:32", LatencyMs: 3.0},
		mdns.DeviceDetails{Hostname: "pi"}, "Acme", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 3.0, true }
	eng.PresenceOnce(context.Background(), &info)

	var offline, updates int
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		switch evt {
		case "device_offline":
			offline++
		case "device_updated":
			updates++
		}
	})

	// Losing the device must still be reported, promptly and exactly once.
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }
	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}
	if offline != 1 {
		t.Fatalf("device_offline fired %d times; want exactly 1", offline)
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatal("device should be offline")
	}

	// And so must its return.
	updates = 0
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 3.0, true }
	eng.PresenceOnce(context.Background(), &info)
	if updates == 0 {
		t.Fatal("coming back online must push a device_updated frame")
	}
}

func TestSweepDoesNotSpamUpdatesForUnchangedDevices(t *testing.T) {
	eng, _, info := discoveryEngine(t, "192.168.0.42")

	// First sweep discovers it.
	if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
		t.Fatalf("DiscoverOnce: %v", err)
	}

	var updates int
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "device_updated" {
			updates++
		}
	})
	// Subsequent sweeps of the same unchanged device should be silent.
	for i := 0; i < 3; i++ {
		if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
			t.Fatalf("DiscoverOnce: %v", err)
		}
	}
	if updates != 0 {
		t.Fatalf("emitted %d frames re-sweeping an unchanged device; want 0", updates)
	}
}

func TestSamePorts(t *testing.T) {
	a := []ports.ServicePort{{Port: 22, Name: "SSH"}, {Port: 80, Name: "HTTP"}}
	if !samePorts(a, a) {
		t.Fatal("a list should equal itself")
	}
	if !samePorts(nil, nil) {
		t.Fatal("two empty lists should be equal")
	}
	if samePorts(a, a[:1]) {
		t.Fatal("different lengths should differ")
	}
	if samePorts(a, []ports.ServicePort{{Port: 22, Name: "SSH"}, {Port: 443, Name: "HTTPS"}}) {
		t.Fatal("different ports should differ")
	}
}

func TestSameStrings(t *testing.T) {
	if !sameStrings(nil, nil) || !sameStrings([]string{"a"}, []string{"a"}) {
		t.Fatal("equal slices should compare equal")
	}
	if sameStrings([]string{"a"}, []string{"b"}) ||
		sameStrings([]string{"a"}, []string{"a", "b"}) ||
		sameStrings([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("unequal slices should compare unequal")
	}
}
