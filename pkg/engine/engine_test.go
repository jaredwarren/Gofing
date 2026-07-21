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
	eng := New(nil)
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
	eng := New(nil)
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.10", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname: "MacBook",
	}, "Apple", now, nil)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.99", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname: "MacBook",
	}, "Apple", now.Add(time.Second), map[string]bool{"00:1C:42:11:22:33": true})

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
	eng := New(nil)
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.20", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname: "Jared's MacBook Pro",
	}, "Private / Randomized MAC", now, nil)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.21", MAC: "3A:11:22:33:44:55"}, mdns.DeviceDetails{
		Hostname: "jared's macbook pro",
	}, "Private / Randomized MAC", now.Add(time.Second), map[string]bool{"3A:45:DB:15:44:3D": true})

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
	eng := New(nil)
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.20", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname: "Jared's MacBook Pro",
	}, "Private", now, nil)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.21", MAC: "3A:11:22:33:44:55"}, mdns.DeviceDetails{
		Hostname: "Someone's iPhone",
	}, "Private", now.Add(time.Second), nil)

	devs := eng.GetDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
}

func TestUpsertUnknownMACFallsBackToIP(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.50", MAC: ""}, mdns.DeviceDetails{
		Hostname: "mystery",
	}, "Unknown", time.Now(), nil)

	devs := eng.GetDevices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].ID != "ip:192.168.1.50" {
		t.Errorf("expected ip: fallback id, got %q", devs[0].ID)
	}
}

func TestDisplayNameAndType(t *testing.T) {
	d := Device{IP: "10.0.0.1", Hostname: "host", Vendor: "Apple", DeviceType: "Computer"}
	if d.DisplayName() != "host" {
		t.Fatalf("DisplayName=%q", d.DisplayName())
	}
	d.CustomName = "My Mac"
	if d.DisplayName() != "My Mac" {
		t.Fatalf("CustomName DisplayName=%q", d.DisplayName())
	}
	if d.DisplayType() != "Computer" {
		t.Fatalf("DisplayType=%q", d.DisplayType())
	}
	d.DeviceTypeOverride = "Laptop"
	if d.DisplayType() != "Laptop" {
		t.Fatalf("override DisplayType=%q", d.DisplayType())
	}
}

func TestPatchDevicePersistsOverrides(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.10", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname:   "MacBook",
		DeviceType: "Computer",
	}, "Apple", time.Now(), nil)

	name := "Office Mac"
	note := "desk"
	override := "Laptop"
	dev, err := eng.PatchDevice("00:1C:42:11:22:33", DevicePatch{
		CustomName:         &name,
		Note:               &note,
		DeviceTypeOverride: &override,
	})
	if err != nil {
		t.Fatalf("PatchDevice: %v", err)
	}
	if dev.CustomName != name || dev.Note != note || dev.DeviceTypeOverride != override {
		t.Fatalf("patch not applied: %+v", dev)
	}

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.10", MAC: "00:1C:42:11:22:33"}, mdns.DeviceDetails{
		Hostname:   "MacBook-Pro",
		DeviceType: "Computer",
	}, "Apple", time.Now(), map[string]bool{"00:1C:42:11:22:33": true})

	got, ok := eng.GetDevice("00:1C:42:11:22:33")
	if !ok {
		t.Fatal("device missing")
	}
	if got.CustomName != name || got.Note != note || got.DeviceTypeOverride != override {
		t.Fatalf("overrides wiped: %+v", got)
	}
	if got.Hostname != "MacBook-Pro" {
		t.Fatalf("hostname not updated: %q", got.Hostname)
	}
}
