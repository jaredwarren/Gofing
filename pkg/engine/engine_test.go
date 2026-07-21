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

func TestScanDevicePortsCommon(t *testing.T) {
	eng := New(nil)
	now := time.Now()
	eng.upsertDevice(scanner.RawDevice{IP: "127.0.0.1", MAC: "00:11:22:33:44:55"}, mdns.DeviceDetails{
		Hostname: "localhost-test",
		NameSource: mdns.NameSourceDNS,
		DeviceType: "Computer",
	}, "Unknown", now, nil)

	open, err := eng.ScanDevicePorts("00:11:22:33:44:55", "common")
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := eng.GetDevice("00:11:22:33:44:55")
	if !ok {
		t.Fatal("device missing")
	}
	if len(dev.OpenPorts) != len(open) {
		t.Fatalf("persisted %d vs returned %d", len(dev.OpenPorts), len(open))
	}
}

func TestScanDevicePortsInvalidMode(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "127.0.0.1", MAC: "00:11:22:33:44:66"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	_, err := eng.ScanDevicePorts("00:11:22:33:44:66", "weird")
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestResolveDeviceNameMissing(t *testing.T) {
	eng := New(nil)
	_, err := eng.ResolveDeviceName("nope")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveDeviceNameKeepsExistingWhenMiss(t *testing.T) {
	prevWarm := warmHostFn
	prevDeep := deepLookupFn
	warmHostFn = func(string) {}
	deepLookupFn = func(*mdns.Resolver, string) mdns.LookupResult { return mdns.LookupResult{} }
	t.Cleanup(func() {
		warmHostFn = prevWarm
		deepLookupFn = prevDeep
	})

	eng := New(nil)
	now := time.Now()
	eng.upsertDevice(scanner.RawDevice{IP: "203.0.113.9", MAC: "AA:BB:CC:DD:EE:FF"}, mdns.DeviceDetails{
		Hostname:   "kept-name",
		NameSource: mdns.NameSourceARP,
		DeviceType: "Computer",
	}, "Apple, Inc.", now, nil)

	res, err := eng.ResolveDeviceName("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	if res.Device.Hostname != "kept-name" {
		t.Fatalf("should keep existing hostname, got %q", res.Device.Hostname)
	}
}

func TestTryStartPortScanRejectsDuplicate(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "127.0.0.1", MAC: "00:11:22:33:44:77"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)

	if !eng.tryBeginPortScan("00:11:22:33:44:77") {
		t.Fatal("first begin should succeed")
	}
	started, err := eng.TryStartPortScan("00:11:22:33:44:77", "common")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("expected already-running to not start another scan")
	}
	eng.endPortScan("00:11:22:33:44:77")
}

func TestHostnameRankUpgradeInEngine(t *testing.T) {
	eng := New(nil)
	now := time.Now()

	// First seen via weak HTTP title
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.142", MAC: "8C:85:90:24:10:B7"}, mdns.DeviceDetails{
		Hostname:   "Some Title",
		NameSource: mdns.NameSourceHTTP,
		DeviceType: "Apple Device",
		Model:      "Apple Device",
	}, "Apple, Inc.", now, nil)

	dev, _ := eng.GetDevice("8C:85:90:24:10:B7")
	if dev.Hostname != "Some Title" || dev.NameSource != mdns.NameSourceHTTP {
		t.Fatalf("initial: %+v", dev)
	}

	// Later ARP Bonjour name must upgrade and persist rank
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.142", MAC: "8C:85:90:24:10:B7", Hostname: "amys-mbp.local"}, mdns.DeviceDetails{
		Hostname:   "amys-mbp",
		NameSource: mdns.NameSourceARP,
		DeviceType: "Computer",
		Model:      "Apple Mac",
	}, "Apple, Inc.", now.Add(time.Second), map[string]bool{"8C:85:90:24:10:B7": true})

	dev, _ = eng.GetDevice("8C:85:90:24:10:B7")
	if dev.Hostname != "amys-mbp" || dev.NameSource != mdns.NameSourceARP {
		t.Fatalf("after ARP upgrade: hostname=%q source=%q", dev.Hostname, dev.NameSource)
	}

	// Weaker DNS must not demote
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.142", MAC: "8C:85:90:24:10:B7"}, mdns.DeviceDetails{
		Hostname:   "other-name",
		NameSource: mdns.NameSourceDNS,
		Model:      "Apple Device",
	}, "Apple, Inc.", now.Add(2*time.Second), map[string]bool{"8C:85:90:24:10:B7": true})

	dev, _ = eng.GetDevice("8C:85:90:24:10:B7")
	if dev.Hostname != "amys-mbp" || dev.NameSource != mdns.NameSourceARP {
		t.Fatalf("DNS should not demote: hostname=%q source=%q", dev.Hostname, dev.NameSource)
	}
}

func TestDisplayNameSkipsGenericModel(t *testing.T) {
	d := Device{IP: "192.168.0.142", Vendor: "Apple, Inc.", Model: "Apple Device", DeviceType: "Apple Device"}
	if d.DisplayName() != "Apple, Inc." {
		t.Fatalf("DisplayName=%q want vendor fallback", d.DisplayName())
	}
	d.Hostname = "AMYS-MBP"
	if d.DisplayName() != "AMYS-MBP" {
		t.Fatalf("DisplayName=%q", d.DisplayName())
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

func TestOfflineDebounceRequiresConsecutiveMisses(t *testing.T) {
	eng := New(nil)
	now := time.Now()
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.132", MAC: "28:CD:C1:01:43:34", LatencyMs: 1}, mdns.DeviceDetails{
		Hostname: "pi",
	}, "Raspberry Pi", now, nil)

	dev, ok := eng.GetDevice(id)
	if !ok || !dev.IsOnline {
		t.Fatal("expected online after discover")
	}

	// Simulate two missed scans — should stay online.
	for i := 0; i < offlineMissThreshold-1; i++ {
		eng.applyMisses(map[string]bool{}, map[string]bool{id: true})
		dev, _ = eng.GetDevice(id)
		if !dev.IsOnline {
			t.Fatalf("went offline after %d miss(es); threshold is %d", i+1, offlineMissThreshold)
		}
	}

	// Third miss flips offline.
	eng.applyMisses(map[string]bool{}, map[string]bool{id: true})
	dev, _ = eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("expected offline after consecutive misses")
	}

	// Seeing it again clears misses and brings online.
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.132", MAC: "28:CD:C1:01:43:34", LatencyMs: 2}, mdns.DeviceDetails{
		Hostname: "pi",
	}, "Raspberry Pi", now.Add(time.Second), map[string]bool{id: false})
	dev, _ = eng.GetDevice(id)
	if !dev.IsOnline {
		t.Fatal("expected online after rediscovery")
	}
	if eng.missCount[id] != 0 {
		t.Fatalf("miss count not reset: %d", eng.missCount[id])
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
	// Hostname stays sticky once sane (avoids garbage overwrites).
	if got.Hostname != "MacBook" {
		t.Fatalf("hostname unexpectedly changed: %q", got.Hostname)
	}
}
