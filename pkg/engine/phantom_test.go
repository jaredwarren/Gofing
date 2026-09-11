package engine

import (
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/ports"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// TestUpsertRefusesToCreateWithoutMAC covers the guard that keeps a probe
// artifact from becoming a permanent inventory row.
func TestUpsertRefusesToCreateWithoutMAC(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)

	var found int
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "device_found" {
			found++
		}
	})

	id := eng.upsertDeviceOpts(
		scanner.RawDevice{IP: "192.168.0.240", MAC: ""}, // a false-positive address
		mdns.DeviceDetails{}, "", time.Now(), nil,
		upsertOpts{Persist: true, EmitFound: true, EmitUpdate: true, RequireMACForNew: true})

	if id != "" {
		t.Fatalf("created device %q from a row with no MAC", id)
	}
	if got := len(eng.GetDevices()); got != 0 {
		t.Fatalf("inventory has %d devices, want 0", got)
	}
	if found != 0 {
		t.Fatalf("emitted %d device_found events for a phantom", found)
	}
}

// A MAC-less row must still be able to confirm a device already known at that
// IP — that is a real device whose ARP entry happened not to resolve.
func TestUpsertWithoutMACStillUpdatesKnownDevice(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)

	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50"},
		mdns.DeviceDetails{Hostname: "nas"}, "Acme", time.Now(), nil)
	eng.mu.Lock()
	eng.devices[id].IsOnline = false
	eng.mu.Unlock()

	got := eng.upsertDeviceOpts(
		scanner.RawDevice{IP: "192.168.0.50", MAC: "", LatencyMs: 2},
		mdns.DeviceDetails{}, "", time.Now(), nil,
		upsertOpts{Persist: true, EmitFound: true, EmitUpdate: true, RequireMACForNew: true})

	if got != id {
		t.Fatalf("matched %q, want the existing device %q", got, id)
	}
	dev, _ := eng.GetDevice(id)
	if !dev.IsOnline {
		t.Error("a MAC-less confirmation should still bring a known device online")
	}
	if dev.MAC != "AA:BB:CC:DD:EE:50" {
		t.Errorf("MAC = %q, want the known MAC preserved", dev.MAC)
	}
}

// Without the flag, the legacy create-anything behavior is unchanged, so the
// other upsert call sites keep working.
func TestUpsertWithoutFlagStillCreatesMAClessRow(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.60", MAC: ""},
		mdns.DeviceDetails{Hostname: "printer"}, "", time.Now(), nil)
	if id == "" {
		t.Fatal("default upsert should still create a device")
	}
}

func TestIsPhantomRow(t *testing.T) {
	tests := []struct {
		name string
		dev  Device
		want bool
	}{
		{"bare MAC-less row", Device{IP: "192.168.0.240"}, true},
		{"MAC-less but typed and vendored is still phantom",
			Device{IP: "192.168.0.240", DeviceType: "Generic Device", Vendor: "Unknown Vendor"}, true},
		{"has a MAC", Device{IP: "192.168.0.5", MAC: "AA:BB:CC:DD:EE:05"}, false},
		{"has a learned hostname", Device{IP: "192.168.0.240", Hostname: "pi"}, false},
		{"user named it", Device{IP: "192.168.0.240", CustomName: "Garage door"}, false},
		{"user annotated it", Device{IP: "192.168.0.240", Note: "check this"}, false},
		{"user overrode the type", Device{IP: "192.168.0.240", DeviceTypeOverride: "NAS"}, false},
		{"has MAC history", Device{IP: "192.168.0.240", PreviousMACs: []string{"AA:BB:CC:DD:EE:01"}}, false},
		{"has port-scan results", Device{IP: "192.168.0.240",
			OpenPorts: []ports.ServicePort{{Port: 22, Name: "SSH"}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPhantomRow(tc.dev); got != tc.want {
				t.Fatalf("isPhantomRow = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoadFromStorePrunesPhantoms(t *testing.T) {
	real1 := Device{ID: "AA:BB:CC:DD:EE:01", IP: "192.168.0.11", MAC: "AA:BB:CC:DD:EE:01",
		Hostname: "hue", DeviceType: "Smart Home", Vendor: "Signify", LastSeen: time.Now()}
	phantom1 := Device{ID: "ip:192.168.0.240", IP: "192.168.0.240",
		DeviceType: "Generic Device", Vendor: "Unknown Vendor", LastSeen: time.Now()}
	phantom2 := Device{ID: "ip:192.168.0.241", IP: "192.168.0.241", LastSeen: time.Now()}
	annotated := Device{ID: "ip:192.168.0.242", IP: "192.168.0.242",
		CustomName: "Mystery box", LastSeen: time.Now()}

	p := newMemPersist(real1, phantom1, phantom2, annotated)
	eng := New(p)

	if _, ok := eng.GetDevice(real1.ID); !ok {
		t.Error("a real device was pruned")
	}
	if _, ok := eng.GetDevice(annotated.ID); !ok {
		t.Error("a user-annotated MAC-less row was pruned; user data must survive")
	}
	for _, id := range []string{phantom1.ID, phantom2.ID} {
		if _, ok := eng.GetDevice(id); ok {
			t.Errorf("phantom %s survived the prune", id)
		}
		if _, ok := p.stored(id); ok {
			t.Errorf("phantom %s was not deleted from the store", id)
		}
	}
}
