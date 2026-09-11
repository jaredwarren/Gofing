package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/dhcp"
	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
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

func TestNetworkKeyAndScopedID(t *testing.T) {
	key := NetworkKeyFromInfo(&network.Info{SSID: "HomeWifi", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1"})
	if key != "ssid:HomeWifi" {
		t.Fatalf("key=%q", key)
	}
	key = NetworkKeyFromInfo(&network.Info{SubnetCIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1"})
	if key != "gw:10.0.0.1@10.0.0.0_24" {
		t.Fatalf("key=%q, want sanitized CIDR (no slash)", key)
	}
	if strings.Contains(key, "/") {
		t.Fatalf("network key must not embed '/': %q", key)
	}
	// Wired placeholder must not become an SSID key — it collapses every ethernet LAN.
	key = NetworkKeyFromInfo(&network.Info{
		SSID: "Wired / Ethernet", SubnetCIDR: "192.168.0.0/24", GatewayIP: "192.168.0.1",
	})
	wantWired := "gw:192.168.0.1@192.168.0.0_24"
	if key != wantWired {
		t.Fatalf("wired placeholder key=%q, want %q", key, wantWired)
	}
	home := NetworkKeyFromInfo(&network.Info{
		SSID: "Wired / Ethernet", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1",
	})
	office := NetworkKeyFromInfo(&network.Info{
		SSID: "Wired / Ethernet", SubnetCIDR: "192.168.0.0/24", GatewayIP: "192.168.0.1",
	})
	if home == office {
		t.Fatalf("distinct wired LANs collided on key %q", home)
	}
	if got := ScopedDeviceID(wantWired, "aa:bb:cc:dd:ee:ff", ""); got != wantWired+"/AA:BB:CC:DD:EE:FF" {
		t.Fatalf("scoped=%q", got)
	} else if strings.Count(got, "/") != 1 {
		t.Fatalf("scoped id should have exactly one separator slash: %q", got)
	}
	if got := ScopedDeviceID("ssid:Home", "aa:bb:cc:dd:ee:ff", ""); got != "ssid:Home/AA:BB:CC:DD:EE:FF" {
		t.Fatalf("scoped=%q", got)
	}
	if got := stripNetworkScope("ssid:Home/AA:BB:CC:DD:EE:FF"); got != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("strip=%q", got)
	}
	// Legacy slash-in-CIDR and corrupted doubled-prefix IDs must still yield the MAC.
	if got := stripNetworkScope("gw:192.168.0.1@192.168.0.0/24/AA:BB:CC:DD:EE:FF"); got != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("strip legacy gw=%q", got)
	}
	if got := stripNetworkScope("gw:192.168.0.1@192.168.0.0/24/24/AA:BB:CC:DD:EE:FF"); got != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("strip corrupted=%q", got)
	}
	if got := stripNetworkScope(wantWired + "/AA:BB:CC:DD:EE:FF"); got != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("strip sanitized=%q", got)
	}
}

func TestReconcileRepairsWiredPlaceholderAndSlashKeys(t *testing.T) {
	eng := New(nil)
	mac := "AA:BB:CC:DD:EE:10"
	// Persisted under the old wired SSID placeholder — invisible under gw: key without migrate.
	eng.devices["ssid:Wired / Ethernet/"+mac] = &Device{
		ID: "ssid:Wired / Ethernet/" + mac, NetworkKey: "ssid:Wired / Ethernet",
		IP: "192.168.0.10", MAC: mac, IsOnline: false, Hostname: "printer",
	}
	// Corrupted ID from first-slash strip on unsanitized CIDR.
	corruptID := "gw:192.168.0.1@192.168.0.0/24/24/" + mac
	eng.devices[corruptID] = &Device{
		ID: corruptID, NetworkKey: "gw:192.168.0.1@192.168.0.0/24",
		IP: "192.168.0.11", MAC: "AA:BB:CC:DD:EE:11", IsOnline: false,
	}

	info := &network.Info{SSID: "Wired / Ethernet", SubnetCIDR: "192.168.0.0/24", GatewayIP: "192.168.0.1"}
	eng.SetActiveNetwork(info)

	wantKey := "gw:192.168.0.1@192.168.0.0_24"
	devs := eng.GetDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 visible devices after reconcile, got %d (%+v)", len(devs), devs)
	}
	for _, d := range devs {
		if d.NetworkKey != wantKey {
			t.Fatalf("device %s NetworkKey=%q, want %q", d.MAC, d.NetworkKey, wantKey)
		}
		if !strings.HasPrefix(d.ID, wantKey+"/") {
			t.Fatalf("device ID %q not under sanitized key", d.ID)
		}
		if strings.Contains(strings.TrimPrefix(d.ID, wantKey+"/"), "/") {
			t.Fatalf("base ID still contains slash: %q", d.ID)
		}
	}
	if _, ok := eng.devices[corruptID]; ok {
		t.Fatal("corrupted map key should have been removed")
	}
}

func TestUpsertRemountDoesNotCorruptGwScopedID(t *testing.T) {
	eng := New(nil)
	info := &network.Info{SSID: "Wired / Ethernet", SubnetCIDR: "192.168.0.0/24", GatewayIP: "192.168.0.1"}
	eng.SetActiveNetwork(info)
	wantKey := NetworkKeyFromInfo(info)

	id1 := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "aa:bb:cc:dd:ee:50", LatencyMs: 1},
		mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	wantID := wantKey + "/AA:BB:CC:DD:EE:50"
	if id1 != wantID {
		t.Fatalf("first upsert id=%q, want %q", id1, wantID)
	}
	id2 := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "aa:bb:cc:dd:ee:50", LatencyMs: 2},
		mdns.DeviceDetails{}, "Unknown", time.Now(), nil)
	if id2 != wantID {
		t.Fatalf("second upsert remounted to %q, want stable %q", id2, wantID)
	}
	if len(eng.devices) != 1 {
		t.Fatalf("devices map grew to %d entries: %#v", len(eng.devices), eng.devices)
	}
	dev := eng.devices[wantID]
	if dev == nil || !dev.IsOnline {
		t.Fatalf("device should be online after upsert, got %+v", dev)
	}
}

func TestGetDevicesHidesOtherNetwork(t *testing.T) {
	eng := New(nil)
	eng.devices["ssid:Home/AA:BB:CC:DD:EE:01"] = &Device{
		ID: "ssid:Home/AA:BB:CC:DD:EE:01", NetworkKey: "ssid:Home",
		IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", IsOnline: false,
	}
	eng.devices["ssid:Cafe/AA:BB:CC:DD:EE:02"] = &Device{
		ID: "ssid:Cafe/AA:BB:CC:DD:EE:02", NetworkKey: "ssid:Cafe",
		IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:02", IsOnline: false,
	}

	eng.SetActiveNetwork(&network.Info{SSID: "Home", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1"})
	devs := eng.GetDevices()
	if len(devs) != 1 || devs[0].MAC != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("expected only home device, got %+v", devs)
	}

	eng.SetActiveNetwork(&network.Info{SSID: "Cafe", SubnetCIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1"})
	devs = eng.GetDevices()
	if len(devs) != 1 || devs[0].MAC != "AA:BB:CC:DD:EE:02" {
		t.Fatalf("expected only cafe device, got %+v", devs)
	}
}

func TestApplyMissesIgnoresOtherNetwork(t *testing.T) {
	eng := New(nil)
	eng.SetActiveNetwork(&network.Info{SSID: "Home", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1"})
	home := &Device{
		ID: "ssid:Home/AA:BB:CC:DD:EE:01", NetworkKey: "ssid:Home",
		IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", IsOnline: true,
	}
	cafe := &Device{
		ID: "ssid:Cafe/AA:BB:CC:DD:EE:02", NetworkKey: "ssid:Cafe",
		IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:02", IsOnline: true,
	}
	eng.devices[home.ID] = home
	eng.devices[cafe.ID] = cafe

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	info := &network.Info{SSID: "Home", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1"}
	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), info)
	}
	if eng.devices[home.ID].IsOnline {
		t.Fatal("home device should be offline after misses")
	}
	if !eng.devices[cafe.ID].IsOnline {
		t.Fatal("cafe device must stay online (other network)")
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
		Hostname:   "localhost-test",
		NameSource: mdns.NameSourceDNS,
		DeviceType: "Computer",
	}, "Unknown", now, nil)

	open, err := eng.ScanDevicePorts(context.Background(), "00:11:22:33:44:55", "common")
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
	_, err := eng.ScanDevicePorts(context.Background(), "00:11:22:33:44:66", "weird")
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestResolveDeviceNameMissing(t *testing.T) {
	eng := New(nil)
	_, err := eng.ResolveDeviceName(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveDeviceNameKeepsExistingWhenMiss(t *testing.T) {
	eng := New(nil)
	eng.setTestHooks(
		func(context.Context, string) {},
		func(context.Context, *mdns.Resolver, string) mdns.LookupResult { return mdns.LookupResult{} },
	)

	now := time.Now()
	eng.upsertDevice(scanner.RawDevice{IP: "203.0.113.9", MAC: "AA:BB:CC:DD:EE:FF"}, mdns.DeviceDetails{
		Hostname:   "kept-name",
		NameSource: mdns.NameSourceARP,
		DeviceType: "Computer",
	}, "Apple, Inc.", now, nil)

	res, err := eng.ResolveDeviceName(context.Background(), "AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	if res.Device.Hostname != "kept-name" {
		t.Fatalf("should keep existing hostname, got %q", res.Device.Hostname)
	}
}

func TestTryStartPortScanIgnoresCancelledCallerContext(t *testing.T) {
	eng := New(nil)
	id := eng.upsertDevice(scanner.RawDevice{IP: "127.0.0.1", MAC: "00:11:22:33:44:88"},
		mdns.DeviceDetails{}, "Unknown", time.Now(), nil)

	done := make(chan struct{})
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "portscan_complete" || evt == "portscan_error" {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulates net/http cancelling r.Context() when the handler returns

	started, err := eng.TryStartPortScan(ctx, id, "common")
	if err != nil {
		t.Fatal(err)
	}
	if !started {
		t.Fatal("expected scan to start")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("port scan did not finish; cancelled caller context likely aborted it")
	}
}

func TestTryStartPortScanRejectsDuplicate(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "127.0.0.1", MAC: "00:11:22:33:44:77"}, mdns.DeviceDetails{}, "Unknown", time.Now(), nil)

	if !eng.tryBeginPortScan("00:11:22:33:44:77") {
		t.Fatal("first begin should succeed")
	}
	started, err := eng.TryStartPortScan(context.Background(), "00:11:22:33:44:77", "common")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("expected already-running to not start another scan")
	}
	eng.endPortScan("00:11:22:33:44:77")
}

func TestApplyCachedHostnames(t *testing.T) {
	eng := New(nil)
	now := time.Now()
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.51", MAC: "70:22:FE:B6:3D:94"}, mdns.DeviceDetails{
		DeviceType: "Mobile Phone",
	}, "Apple, Inc.", now, nil)

	dev, ok := eng.GetDevice("70:22:FE:B6:3D:94")
	if !ok || dev.Hostname != "" {
		t.Fatalf("expected empty hostname, got ok=%v hostname=%q", ok, dev.Hostname)
	}

	// Background browse learns the Bonjour name after the device was fingerprinted.
	_ = eng.mdnsResolver.ResolveDevice("192.168.0.51", "70:22:FE:B6:3D:94", "Apple, Inc.", false, "", "Amys-new-iPhone.local")
	eng.applyCachedHostnames()

	dev, _ = eng.GetDevice("70:22:FE:B6:3D:94")
	if dev.Hostname != "Amys-new-iPhone" {
		t.Fatalf("cached hostname not applied: %q", dev.Hostname)
	}
	if dev.NameSource != mdns.NameSourceARP {
		t.Fatalf("source=%q", dev.NameSource)
	}
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

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	// Misses short of the threshold must not flip it.
	for i := 0; i < offlineMissThreshold-1; i++ {
		eng.PresenceOnce(context.Background(), nil)
		dev, _ = eng.GetDevice(id)
		if !dev.IsOnline {
			t.Fatalf("went offline after %d miss(es); threshold is %d", i+1, offlineMissThreshold)
		}
	}

	// The threshold miss flips offline.
	eng.PresenceOnce(context.Background(), nil)
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

func TestUpsertPrivateMACGenericHostnameDoesNotMerge(t *testing.T) {
	eng := New(nil)
	now := time.Now()

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.100", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname: "iPhone",
	}, "Private / Randomized MAC", now, nil)

	eng.upsertDevice(scanner.RawDevice{IP: "192.168.1.101", MAC: "3A:99:88:77:66:55"}, mdns.DeviceDetails{
		Hostname: "iPhone",
	}, "Private / Randomized MAC", now.Add(time.Second), nil)

	devs := eng.GetDevices()
	if len(devs) != 2 {
		t.Fatalf("expected 2 distinct devices for generic hostname 'iPhone', got %d", len(devs))
	}
}

func TestImportDHCPLeasesCreatesOfflineNamedDevice(t *testing.T) {
	eng := New(nil)
	eng.SetActiveNetwork(&network.Info{SSID: "Home", SubnetCIDR: "192.168.0.0/24", GatewayIP: "192.168.0.1"})

	res := eng.ImportDHCPLeases([]dhcp.Lease{{
		Hostname: "Amys-MBP",
		MAC:      "8c:85:90:24:10:b7",
		IP:       "192.168.0.142",
	}})
	if res.Created != 1 {
		t.Fatalf("created=%d %+v", res.Created, res)
	}
	dev, ok := eng.GetDevice("ssid:Home/8C:85:90:24:10:B7")
	if !ok {
		t.Fatal("device missing")
	}
	if dev.Hostname != "Amys-MBP" || dev.NameSource != mdns.NameSourceDHCP {
		t.Fatalf("hostname=%q source=%q", dev.Hostname, dev.NameSource)
	}
	if dev.IsOnline {
		t.Fatal("DHCP import must not mark devices online")
	}

	res = eng.ImportDHCPLeases([]dhcp.Lease{{
		Hostname: "---",
		MAC:      "AA:BB:CC:DD:EE:01",
		IP:       "192.168.0.10",
	}})
	if res.Skipped == 0 {
		t.Fatal("unnamed lease should be skipped")
	}
}

func TestImportDHCPLeasesDoesNotDemoteHost(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.72", MAC: "3A:45:DB:15:44:3D"}, mdns.DeviceDetails{
		Hostname:   "Jareds-MBP",
		NameSource: mdns.NameSourceHost,
	}, "Apple", time.Now(), nil)

	res := eng.ImportDHCPLeases([]dhcp.Lease{{
		Hostname: "android-dhcp-xyz",
		MAC:      "3A:45:DB:15:44:3D",
		IP:       "192.168.0.99",
	}})
	if res.Updated != 1 {
		t.Fatalf("expected IP update, got %+v", res)
	}
	dev, _ := eng.GetDevice("3A:45:DB:15:44:3D")
	if dev.Hostname != "Jareds-MBP" || dev.NameSource != mdns.NameSourceHost {
		t.Fatalf("host name lost: %q/%q", dev.Hostname, dev.NameSource)
	}
	if dev.IP != "192.168.0.99" {
		t.Fatalf("ip=%q", dev.IP)
	}
}

func TestOnNameLearnedAppliesMDNS(t *testing.T) {
	eng := New(nil)
	eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.142", MAC: "8C:85:90:24:10:B7"}, mdns.DeviceDetails{
		DeviceType: "Computer",
	}, "Apple", time.Now(), nil)

	var events int
	eng.RegisterEventListener(func(eventType string, data interface{}) {
		if eventType == "device_updated" {
			events++
		}
	})
	eng.onNameLearned("192.168.0.142", "Amys-MBP", mdns.NameSourceMDNS)
	dev, _ := eng.GetDevice("8C:85:90:24:10:B7")
	if dev.Hostname != "Amys-MBP" || dev.NameSource != mdns.NameSourceMDNS {
		t.Fatalf("%q/%q", dev.Hostname, dev.NameSource)
	}
	if events != 1 {
		t.Fatalf("events=%d", events)
	}

	eng.onNameLearned("192.168.0.142", "iPad (73)", mdns.NameSourceMDNS)
	dev, _ = eng.GetDevice("8C:85:90:24:10:B7")
	if dev.Hostname != "Amys-MBP" {
		t.Fatalf("equal-rank flap: %q", dev.Hostname)
	}
}

func TestAdoptDeviceMetadataMatchesByIP(t *testing.T) {
	eng := New(nil)
	info := &network.Info{GatewayIP: "192.168.0.1", SubnetCIDR: "192.168.0.0/24", SSID: "Home"}
	eng.SetActiveNetwork(info)
	now := time.Now()

	// Seed existing offline iPad device on 192.168.0.156
	id1 := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.156", MAC: "68:2F:67:0E:CD:44"}, mdns.DeviceDetails{
		Hostname:   "iPad-73",
		Model:      "iPad",
		DeviceType: "tablet",
	}, "Apple, Inc.", now, nil)
	eng.mu.Lock()
	eng.devices[id1].IsOnline = false
	eng.mu.Unlock()

	// New device connects with a private/randomized MAC at the same IP
	id2 := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.156", MAC: "AE:35:05:49:5A:0C"}, mdns.DeviceDetails{}, "Private / Randomized MAC", now.Add(time.Second), nil)

	dev2, ok := eng.GetDevice(id2)
	if !ok {
		t.Fatal("device 2 not found")
	}
	if dev2.Hostname != "iPad-73" {
		t.Fatalf("expected device to adopt hostname 'iPad-73', got %q", dev2.Hostname)
	}
	if dev2.Model != "iPad" {
		t.Fatalf("expected device to adopt model 'iPad', got %q", dev2.Model)
	}
	if dev2.Vendor != "Apple, Inc." {
		t.Fatalf("expected device to adopt vendor 'Apple, Inc.', got %q", dev2.Vendor)
	}
	if dev2.DisplayName() != "iPad-73" {
		t.Fatalf("expected DisplayName 'iPad-73', got %q", dev2.DisplayName())
	}
}

func TestDisplayNameNeverGenericVendor(t *testing.T) {
	d := Device{
		IP:     "192.168.0.156",
		MAC:    "AE:35:05:49:5A:0C",
		Vendor: "Private / Randomized MAC",
	}
	if d.DisplayName() == "Private / Randomized MAC" {
		t.Fatalf("DisplayName must never return 'Private / Randomized MAC', got %q", d.DisplayName())
	}
	if d.DisplayName() != "192.168.0.156" {
		t.Fatalf("expected fallback to IP '192.168.0.156', got %q", d.DisplayName())
	}
}
