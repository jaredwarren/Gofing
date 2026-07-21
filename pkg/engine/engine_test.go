package engine

import (
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/scanner"
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

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"},
		{"AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"},
		{"aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeMAC(tt.in); got != tt.want {
			t.Errorf("NormalizeMAC(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestDeviceID(t *testing.T) {
	if got := DeviceID("aa:bb:cc:dd:ee:ff", "192.168.1.5"); got != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC id = %q", got)
	}
	if got := DeviceID("", "192.168.1.5"); got != "ip:192.168.1.5" {
		t.Errorf("IP fallback id = %q", got)
	}
	if got := DeviceID("", ""); got != "" {
		t.Errorf("empty id = %q", got)
	}
}

func TestIsPrivateMAC(t *testing.T) {
	// U/L bit set: second least-significant bit of first octet
	if !IsPrivateMAC("3A:45:DB:15:44:3D") {
		t.Error("expected 3A:... private")
	}
	if !IsPrivateMAC("02:00:00:00:00:01") {
		t.Error("expected 02:... private")
	}
	if IsPrivateMAC("00:1C:42:11:22:33") {
		t.Error("expected 00:1C:42... not private")
	}
	if IsPrivateMAC("") {
		t.Error("empty should not be private")
	}
}

func TestUpsertStableMACKeepsIDOnIPChange(t *testing.T) {
	eng := New()
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.10", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname: "MacBook",
	}, "Apple", now)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.99", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname: "MacBook",
	}, "Apple", now.Add(time.Second))

	devs := eng.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].ID != "00:1C:42:11:22:33" {
		t.Errorf("id changed: %q", devs[0].ID)
	}
	if devs[0].IP != "192.168.1.99" {
		t.Errorf("ip not updated: %q", devs[0].IP)
	}
}

func TestUpsertPrivateMACMergesOnHostname(t *testing.T) {
	eng := New()
	now := time.Now()

	// Different IPs so merge must use hostname rule (not IP match).
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.20", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname: "Jared's MacBook Pro",
	}, "Private / Randomized MAC", now)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.21", MAC: "3A:11:22:33:44:55"}, mdns.DeviceDetails{
		Hostname: "jared's macbook pro", // case-insensitive match
	}, "Private / Randomized MAC", now.Add(time.Second))

	devs := eng.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("expected merge to 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.ID != "3A:45:DB:15:44:3D" {
		t.Errorf("expected original ID kept, got %q", d.ID)
	}
	if d.MAC != "3A:11:22:33:44:55" {
		t.Errorf("expected new MAC, got %q", d.MAC)
	}
	if d.IP != "192.168.1.21" {
		t.Errorf("expected updated IP, got %q", d.IP)
	}
	if len(d.PreviousMACs) != 1 || d.PreviousMACs[0] != "3A:45:DB:15:44:3D" {
		t.Errorf("previous_macs = %#v", d.PreviousMACs)
	}
}

func TestUpsertPrivateMACDifferentHostnameCreatesNew(t *testing.T) {
	eng := New()
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.20", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname: "Jared's MacBook Pro",
	}, "Private", now)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.21", MAC: "3A:11:22:33:44:55"}, mdns.DeviceDetails{
		Hostname: "Someone's iPhone",
	}, "Private", now.Add(time.Second))

	devs := eng.GetDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
}

func TestUpsertUnknownMACFallsBackToIP(t *testing.T) {
	eng := New()
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.50", MAC: ""}, mdns.DeviceDetails{
		Hostname: "mystery",
	}, "Unknown", time.Now())

	devs := eng.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].ID != "ip:192.168.1.50" {
		t.Errorf("expected ip: fallback id, got %q", devs[0].ID)
	}
}
