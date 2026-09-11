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

func seedOfflineDevice(eng *Engine, ip, mac, host string) string {
	id := eng.upsertDevice(scanner.RawDevice{IP: ip, MAC: mac}, mdns.DeviceDetails{
		Hostname: host,
	}, "Unknown", time.Now(), nil)
	eng.mu.Lock()
	eng.devices[id].IsOnline = false
	eng.mu.Unlock()
	return id
}

func TestProbeKnownARPMarksOnlineWithoutStartupAlert(t *testing.T) {
	eng := New(nil)
	id := seedOfflineDevice(eng, "192.168.0.50", "AA:BB:CC:DD:EE:50", "cam")

	var onlineAlerts atomic.Int32
	var updates atomic.Int32
	eng.RegisterEventListener(func(eventType string, data interface{}) {
		if eventType == "device_updated" {
			updates.Add(1)
		}
		if eventType != "alert" {
			return
		}
		if data.(Alert).Rule == "device_online" {
			onlineAlerts.Add(1)
		}
	})

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50", Iface: "en0",
		}}, nil
	}
	var extraProbes atomic.Int32
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		extraProbes.Add(1)
		return 0, false
	}

	info := &network.Info{SubnetCIDR: "192.168.0.0/24", InterfaceName: "en0"}
	hits, ids := eng.probeKnown(context.Background(), info)
	if !ids[id] {
		t.Fatalf("expected confirmed id, hits=%v ids=%v", hits, ids)
	}
	if _, ok := hits["192.168.0.50"]; !ok {
		t.Fatalf("expected skip hit for IP, hits=%v", hits)
	}
	dev, _ := eng.GetDevice(id)
	if !dev.IsOnline {
		t.Fatal("expected online from ARP")
	}
	if updates.Load() < 1 {
		t.Fatal("expected device_updated SSE")
	}
	if onlineAlerts.Load() != 0 {
		t.Fatalf("startup must not alert device_online, got %d", onlineAlerts.Load())
	}
	eng.mu.Lock()
	cleared := !eng.startupPresence
	eng.mu.Unlock()
	if !cleared {
		t.Fatal("startupPresence should clear after first probeKnown")
	}
	if extraProbes.Load() != 0 {
		t.Fatalf("ARP-confirmed device should not be probed, probes=%d", extraProbes.Load())
	}
}

func TestProbeKnownProbeHitAndMiss(t *testing.T) {
	eng := New(nil)
	live := seedOfflineDevice(eng, "192.168.0.10", "AA:BB:CC:DD:EE:10", "pi")
	dead := seedOfflineDevice(eng, "192.168.0.11", "AA:BB:CC:DD:EE:11", "nas")

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return nil, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		if ip == "192.168.0.10" {
			return 3.2, true
		}
		return 0, false
	}

	hits, ids := eng.probeKnown(context.Background(), &network.Info{SubnetCIDR: "192.168.0.0/24", InterfaceName: "en0"})
	if !ids[live] {
		t.Fatalf("live device should be confirmed, ids=%v", ids)
	}
	if ids[dead] {
		t.Fatal("miss should not be confirmed")
	}
	if hits["192.168.0.10"] != 3.2 {
		t.Fatalf("hits=%v", hits)
	}

	on, _ := eng.GetDevice(live)
	off, _ := eng.GetDevice(dead)
	if !on.IsOnline {
		t.Fatal("probe hit should be online")
	}
	if on.LatencyMs != 3.2 {
		t.Fatalf("latency=%v", on.LatencyMs)
	}
	if off.IsOnline {
		t.Fatal("probe miss should stay offline")
	}
}

func TestProbeKnownSecondPassAlerts(t *testing.T) {
	eng := New(nil)
	info := &network.Info{SubnetCIDR: "192.168.0.0/24", InterfaceName: "en0"}
	eng.netDetectFn = func() (*network.Info, error) {
		return info, nil
	}
	id := seedOfflineDevice(eng, "192.168.0.20", "AA:BB:CC:DD:EE:20", "tv")
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	_, _ = eng.probeKnown(context.Background(), info)
	dev, _ := eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("first pass miss should stay offline")
	}

	var onlineAlerts atomic.Int32
	eng.RegisterEventListener(func(eventType string, data interface{}) {
		if eventType == "alert" && data.(Alert).Rule == "device_online" {
			onlineAlerts.Add(1)
		}
	})
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 1.0, true }
	_, ids := eng.probeKnown(context.Background(), info)
	if !ids[id] {
		t.Fatal("second pass should confirm")
	}
	dev, _ = eng.GetDevice(id)
	if !dev.IsOnline {
		t.Fatal("expected online on second pass")
	}
	if onlineAlerts.Load() != 1 {
		t.Fatalf("expected device_online alert after startup, got %d", onlineAlerts.Load())
	}
}

func TestProbeKnownIgnoresOtherIfaceARP(t *testing.T) {
	eng := New(nil)
	id := seedOfflineDevice(eng, "192.168.0.50", "AA:BB:CC:DD:EE:50", "cam")
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50", Iface: "en1",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	_, ids := eng.probeKnown(context.Background(), &network.Info{
		SubnetCIDR: "192.168.0.0/24", InterfaceName: "en0",
	})
	if ids[id] {
		t.Fatal("other-iface ARP must not confirm presence")
	}
	dev, _ := eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("should stay offline")
	}
}

func TestProbeKnownIgnoresOtherNetwork(t *testing.T) {
	eng := New(nil)
	eng.SetActiveNetwork(&network.Info{SSID: "Home", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1"})
	home := &Device{
		ID: "ssid:Home/AA:BB:CC:DD:EE:01", NetworkKey: "ssid:Home",
		IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01", IsOnline: false,
	}
	cafe := &Device{
		ID: "ssid:Cafe/AA:BB:CC:DD:EE:02", NetworkKey: "ssid:Cafe",
		IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:02", IsOnline: false,
	}
	eng.devices[home.ID] = home
	eng.devices[cafe.ID] = cafe

	var probedCafe atomic.Bool
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		if ip == "10.0.0.5" {
			probedCafe.Store(true)
		}
		return 1, true
	}

	_, ids := eng.probeKnown(context.Background(), &network.Info{
		SSID: "Home", SubnetCIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1",
	})
	if !ids[home.ID] || ids[cafe.ID] {
		t.Fatalf("ids=%v", ids)
	}
	if probedCafe.Load() {
		t.Fatal("must not probe other-network device")
	}
	if !eng.devices[home.ID].IsOnline {
		t.Fatal("home should be online")
	}
	if eng.devices[cafe.ID].IsOnline {
		t.Fatal("cafe must stay offline")
	}
}

// TestPresenceSkipsMissConfirmedMidPass covers the guard that replaced the old
// scanGen counter. While a presence pass is probing, another tier — the sweep,
// the mDNS listener, a DHCP import — can prove a device present. Our pass's
// miss is then stale evidence and must not count toward the offline debounce.
func TestPresenceSkipsMissConfirmedMidPass(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.41", MAC: "AA:BB:CC:DD:EE:41", LatencyMs: 1},
		mdns.DeviceDetails{Hostname: "pi"}, "Acme", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		// Stand in for another tier confirming the device while we probe.
		eng.mu.Lock()
		if d, ok := eng.devices[id]; ok {
			d.LastSeen = time.Now()
		}
		eng.mu.Unlock()
		return 0, false
	}

	for i := 0; i < offlineMissThreshold+2; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}

	eng.mu.RLock()
	misses := eng.missCount[id]
	eng.mu.RUnlock()
	if misses != 0 {
		t.Fatalf("missCount = %d; a miss older than the last sighting must not count", misses)
	}
	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Fatal("device was marked offline on stale evidence")
	}
}

func TestPresenceCountsMissWhenNothingElseConfirms(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.42", MAC: "AA:BB:CC:DD:EE:42", LatencyMs: 1},
		mdns.DeviceDetails{Hostname: "pi"}, "Acme", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	// The mirror of the test above: with nobody vouching for it, the debounce
	// must still retire the device.
	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatalf("device should be offline after %d misses", offlineMissThreshold)
	}
}

func TestPresenceEnqueuesWokeDevice(t *testing.T) {
	eng := New(nil)
	eng.notifyFn = func(string, string) error { return nil }
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := seedOfflineDevice(eng, "192.168.0.43", "AA:BB:CC:DD:EE:43", "")

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 2.0, true }

	// A device that wakes up should be fingerprinted promptly — behaviour the
	// old every-30s full scan provided by accident.
	eng.PresenceOnce(context.Background(), &info)
	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Fatal("device should be online")
	}
	pending, inflight := eng.enrichQ.stats()
	if pending+inflight == 0 {
		t.Fatal("a device that came online was not queued for enrichment")
	}
}

func TestPresencePostProbeARPBringsOnline(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := seedOfflineDevice(eng, "192.168.0.44", "AA:BB:CC:DD:EE:44", "iphone")

	var arpCalls atomic.Int32
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		call := arpCalls.Add(1)
		// On the first call (pre-probe), the device is not in the ARP table.
		// On the second call (post-probe), probing provoked an ARP reply.
		if call > 1 {
			return []scanner.RawDevice{{
				IP:    "192.168.0.44",
				MAC:   "AA:BB:CC:DD:EE:44",
				Iface: "en0",
			}}, nil
		}
		return nil, nil
	}
	// The device ignores ICMP and TCP probes (stealth mode / locked smartphone)
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 0, false
	}

	res := eng.PresenceOnce(context.Background(), &info)
	if !res.IDs[id] {
		t.Fatalf("expected device %s to be confirmed by post-probe ARP, IDs=%v", id, res.IDs)
	}
	dev, ok := eng.GetDevice(id)
	if !ok || !dev.IsOnline {
		t.Fatalf("expected device to be marked online, got ok=%v, dev=%+v", ok, dev)
	}
}

func TestPresenceDetectsDHCPNewIPViaARP(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := seedOfflineDevice(eng, "192.168.0.45", "AA:BB:CC:DD:EE:45", "laptop")

	// Device reconnected with a new IP (e.g. DHCP lease renewal)
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP:    "192.168.0.99",
			MAC:   "AA:BB:CC:DD:EE:45",
			Iface: "en0",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 0, false
	}

	res := eng.PresenceOnce(context.Background(), &info)
	if !res.IDs[id] {
		t.Fatalf("expected device %s to be confirmed under new IP, IDs=%v", id, res.IDs)
	}
	dev, ok := eng.GetDevice(id)
	if !ok || !dev.IsOnline {
		t.Fatalf("expected device to be marked online")
	}
	if dev.IP != "192.168.0.99" {
		t.Fatalf("expected dev.IP to be updated to 192.168.0.99, got %s", dev.IP)
	}
}

func TestPerformScanBringsOfflineDeviceOnline(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := seedOfflineDevice(eng, "192.168.0.46", "AA:BB:CC:DD:EE:46", "reconnected-dev")

	// Mock presence to verify it and mock sweepSubnet to return an empty list
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP:    "192.168.0.46",
			MAC:   "AA:BB:CC:DD:EE:46",
			Iface: "en0",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 1.5, true
	}
	eng.sweepFn = func(ctx context.Context, subnetCIDR, iface string, skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
		return nil, nil
	}

	devs, err := eng.PerformScan(context.Background(), &info)
	if err != nil {
		t.Fatalf("PerformScan failed: %v", err)
	}

	var foundOnline bool
	for _, d := range devs {
		if d.ID == id && d.IsOnline {
			foundOnline = true
			break
		}
	}
	if !foundOnline {
		t.Fatalf("expected device %s to be online after PerformScan, devs=%+v", id, devs)
	}
}

func TestStartupOfflineDevicesWithWiredPlaceholderVisible(t *testing.T) {
	eng := New(nil)
	// Seed an offline device with legacy sanitized wired placeholder key
	wiredDev := &Device{
		ID:         "ssid:Wired _ Ethernet/AA:BB:CC:DD:EE:99",
		NetworkKey: "ssid:Wired _ Ethernet",
		IP:         "192.168.0.99",
		MAC:        "AA:BB:CC:DD:EE:99",
		IsOnline:   false,
	}
	eng.devices[wiredDev.ID] = wiredDev

	info := &network.Info{
		GatewayIP:     "192.168.0.1",
		SubnetCIDR:    "192.168.0.0/24",
		SSID:          "Wired / Ethernet",
		InterfaceName: "en0",
	}
	eng.SetActiveNetwork(info)

	devs := eng.GetDevices()
	var found bool
	for _, d := range devs {
		if d.MAC == "AA:BB:CC:DD:EE:99" {
			found = true
			if d.NetworkKey != "gw:192.168.0.1@192.168.0.0_24" {
				t.Fatalf("expected NetworkKey to be reconciled to active gw key, got %s", d.NetworkKey)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected offline wired placeholder device to be visible in GetDevices after SetActiveNetwork")
	}
}

func TestPresenceOnlineDeviceGoesOfflineDespiteStaleARP(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)

	// Simulate device online
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.77", MAC: "AA:BB:CC:DD:EE:77"}, mdns.DeviceDetails{
		Hostname: "my-phone",
	}, "Apple, Inc.", time.Now(), nil)

	dev, ok := eng.GetDevice(id)
	if !ok || !dev.IsOnline {
		t.Fatal("device should be online initially")
	}

	// Device disconnects: active probe fails and reachability-aware ARP excludes it.
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return nil, nil
	}
	// Active probe fails because the device is disconnected.
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 0, false
	}

	for i := 0; i < offlineMissThreshold-1; i++ {
		eng.PresenceOnce(context.Background(), &info)
		dev, _ = eng.GetDevice(id)
		if !dev.IsOnline {
			t.Fatalf("device should remain online after %d miss(es) (debounce)", i+1)
		}
	}

	// Final miss reaches offlineMissThreshold
	eng.PresenceOnce(context.Background(), &info)
	dev, _ = eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatalf("device must be marked offline after %d misses", offlineMissThreshold)
	}

	// Device remains offline on subsequent passes (no flapping)
	eng.PresenceOnce(context.Background(), &info)
	dev, _ = eng.GetDevice(id)
	if dev.IsOnline {
		t.Fatal("device must stay offline on subsequent passes (must not flap)")
	}
}

func TestPresenceSilentDeviceDoesNotFlap(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)

	// iPad or Nintendo Switch: present on the LAN, confirmed by ARP, but drops ICMP and TCP
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.156", MAC: "AE:35:05:49:5A:0C"}, mdns.DeviceDetails{
		Hostname: "iPad",
	}, "Apple, Inc.", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP:    "192.168.0.156",
			MAC:   "AE:35:05:49:5A:0C",
			Iface: "en0",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 0, false // drops ICMP ping and has no common TCP ports open
	}

	for pass := 1; pass <= 10; pass++ {
		eng.PresenceOnce(context.Background(), &info)
		dev, ok := eng.GetDevice(id)
		if !ok {
			t.Fatalf("pass %d: device missing", pass)
		}
		if !dev.IsOnline {
			t.Fatalf("pass %d: silent device falsely went offline (flapping)", pass)
		}
		eng.mu.RLock()
		misses := eng.missCount[id]
		eng.mu.RUnlock()
		if misses != 0 {
			t.Fatalf("pass %d: silent device miss count = %d, want 0", pass, misses)
		}
	}
}

func TestCurrentNetInfoUpdatesActiveNetworkKey(t *testing.T) {
	eng := New(nil)
	home := netInfoFor("192.168.0.0/24", "192.168.0.1")
	home.SSID = "Home"
	eng.SetActiveNetwork(&home)

	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50"}, mdns.DeviceDetails{
		Hostname: "cam",
	}, "Unknown", time.Now(), nil)
	eng.mu.Lock()
	eng.missCount[id] = 2
	oldKey := eng.activeNetworkKey
	eng.mu.Unlock()

	office := netInfoFor("10.0.0.0/24", "10.0.0.1")
	office.SSID = "Office"
	office.IP = "10.0.0.2"

	var changed atomic.Int32
	eng.RegisterEventListener(func(eventType string, _ interface{}) {
		if eventType == "network_changed" {
			changed.Add(1)
		}
	})
	eng.netDetectFn = func() (*network.Info, error) {
		cp := office
		return &cp, nil
	}

	got := eng.currentNetInfo(0)
	if got == nil || got.SSID != "Office" {
		t.Fatalf("currentNetInfo = %+v, want Office", got)
	}

	eng.mu.RLock()
	newKey := eng.activeNetworkKey
	misses := eng.missCount[id]
	eng.mu.RUnlock()
	wantKey := NetworkKeyFromInfo(&office)
	if newKey == oldKey {
		t.Fatal("activeNetworkKey must follow the OS network change")
	}
	if newKey != wantKey {
		t.Fatalf("activeNetworkKey = %q, want %q", newKey, wantKey)
	}
	if misses != 0 {
		t.Fatalf("miss counts for previous LAN must reset, got %d", misses)
	}
	if changed.Load() != 1 {
		t.Fatalf("network_changed emissions = %d, want 1", changed.Load())
	}

	detects := 0
	eng.netDetectFn = func() (*network.Info, error) {
		detects++
		cp := office
		return &cp, nil
	}
	_ = eng.currentNetInfo(30 * time.Second)
	if detects != 0 {
		t.Fatal("fresh netInfo cache must not re-detect")
	}
}

func TestCurrentNetInfoPreventsFalseOfflineOnNetworkSwitch(t *testing.T) {
	// Regression for C6: presence used to refresh netInfo (new subnet/iface) while
	// activeNetworkKey stayed on the old LAN, so Home devices were still probed
	// against the Office network and falsely marked offline.
	eng := New(nil)
	home := netInfoFor("192.168.0.0/24", "192.168.0.1")
	home.SSID = "Home"
	eng.SetActiveNetwork(&home)

	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.77", MAC: "AA:BB:CC:DD:EE:77"}, mdns.DeviceDetails{
		Hostname: "phone",
	}, "Apple, Inc.", time.Now(), nil)

	office := netInfoFor("10.0.0.0/24", "10.0.0.1")
	office.SSID = "Office"
	office.IP = "10.0.0.2"
	eng.netDetectFn = func() (*network.Info, error) {
		cp := office
		return &cp, nil
	}
	info := eng.currentNetInfo(0)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return nil, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		t.Fatalf("home device must not be probed after switching to office; probed %s", ip)
		return 0, false
	}

	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), info)
	}
	dev, ok := eng.GetDevice(id)
	if !ok {
		t.Fatal("device missing")
	}
	if !dev.IsOnline {
		t.Fatal("home device must stay online (not visible / not probed) after network switch")
	}
}

func TestPresenceDiscardsApplyWhenNetworkKeyFlipsMidPass(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)

	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.40", MAC: "AA:BB:CC:DD:EE:40"}, mdns.DeviceDetails{
		Hostname: "nas",
	}, "Unknown", time.Now(), nil)

	office := netInfoFor("10.0.0.0/24", "10.0.0.1")
	office.SSID = "Office"
	officeKey := NetworkKeyFromInfo(&office)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return nil, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		// Flip the key without setActiveNetworkLocked so miss counters are not
		// cleared — proving the apply-phase discard is what protects us.
		eng.mu.Lock()
		eng.activeNetworkKey = officeKey
		eng.activeSubnetCIDR = office.SubnetCIDR
		eng.mu.Unlock()
		return 0, false
	}

	eng.PresenceOnce(context.Background(), &info)

	eng.mu.RLock()
	misses := eng.missCount[id]
	online := eng.devices[id].IsOnline
	eng.mu.RUnlock()
	if misses != 0 {
		t.Fatalf("discarded apply must not count a miss, got %d", misses)
	}
	if !online {
		t.Fatal("device must stay online when apply is discarded")
	}
}

// TestPresenceDoesNotFlapWhenARPVouches is the regression test for observed
// offline/online churn: 121 transitions in 14 minutes across a fleet where
// every device had a live kernel ARP entry.
//
// The device here is present in ARP but answers no active probe — a sleeping
// iPad with a duty-cycled radio and no open TCP ports. Presence must keep it
// online on Layer-2 evidence alone.
func TestPresenceDoesNotFlapWhenARPVouches(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.103", MAC: "56:B3:F7:E3:A7:53", LatencyMs: 5},
		mdns.DeviceDetails{Hostname: "sleepy-ipad"}, "Apple", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.103", MAC: "56:B3:F7:E3:A7:53", Iface: "en0",
		}}, nil
	}
	// Nothing answers, ever — neither the quick nor the patient probe.
	var probes atomic.Int32
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		probes.Add(1)
		return 0, false
	}

	var offlineEvents atomic.Int32
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "device_offline" {
			offlineEvents.Add(1)
		}
	})

	// Run well past the miss threshold, but stop short of a verification pass.
	for i := 0; i < presenceVerifyEvery-1; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}

	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Fatal("device in the ARP table was marked offline; this is the flapping bug")
	}
	if offlineEvents.Load() != 0 {
		t.Fatalf("emitted %d device_offline events for an ARP-present device", offlineEvents.Load())
	}
	if probes.Load() != 0 {
		t.Fatalf("probed an ARP-vouched device %d times on non-verify passes", probes.Load())
	}
}

// TestPresenceKeepsSilentDeviceOnlineIndefinitely is the regression test for a
// false-negative I introduced: verification asked whether a device replied to a
// patient probe, and retired it after three failures.
//
// A Nintendo Switch in standby (BC:9E:BB, measured on the development LAN)
// answers no ICMP and opens no TCP port, while its ARP entry stays resolved
// through repeated probing. Under the reply-based rule it went offline after
// about 3.4 minutes, every time. Layer-2 presence must outlast any number of
// verification passes.
func TestPresenceKeepsSilentDeviceOnlineIndefinitely(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.105", MAC: "BC:9E:BB:8B:49:06"},
		mdns.DeviceDetails{Hostname: "switch"}, "Nintendo Co., Ltd.", time.Now(), nil)

	// ARP always vouches; nothing ever answers a probe.
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		return []scanner.RawDevice{{
			IP: "192.168.0.105", MAC: "BC:9E:BB:8B:49:06", Iface: "en0",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	// Well past several verification passes and the miss threshold.
	passes := presenceVerifyEvery * (offlineMissThreshold + 2)
	for i := 0; i < passes; i++ {
		eng.PresenceOnce(context.Background(), &info)
		if dev, _ := eng.GetDevice(id); !dev.IsOnline {
			t.Fatalf("silent ARP-backed device retired on pass %d of %d", i+1, passes)
		}
	}
}

// TestPresenceRetiresWhenARPEntryGoesStale covers the other half. Departure
// shows up as the kernel entry going away — macOS revalidates roughly every
// arp_llreach_base seconds and drops a non-responder to `(incomplete)`, which
// the parser discards — not as a probe falling silent.
func TestPresenceRetiresWhenARPEntryGoesStale(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.104", MAC: "AA:BB:CC:DD:EE:04"},
		mdns.DeviceDetails{Hostname: "departed"}, "Acme", time.Now(), nil)

	present := true
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) {
		if !present {
			return nil, nil // revalidation failed; entry is gone
		}
		return []scanner.RawDevice{{
			IP: "192.168.0.104", MAC: "AA:BB:CC:DD:EE:04", Iface: "en0",
		}}, nil
	}
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }
	eng.verifyFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	eng.PresenceOnce(context.Background(), &info)
	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Fatal("device should start online while ARP vouches")
	}

	present = false
	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatalf("device should be retired %d passes after its ARP entry went stale",
			offlineMissThreshold)
	}
}

// TestPresenceStillRetiresARPAbsentDevicesQuickly guards the fast path: a
// device that drops out of ARP and answers nothing should go offline on the
// normal threshold, not wait for a verification pass.
func TestPresenceStillRetiresARPAbsentDevicesQuickly(t *testing.T) {
	eng := New(nil)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")
	eng.SetActiveNetwork(&info)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.105", MAC: "AA:BB:CC:DD:EE:05", LatencyMs: 5},
		mdns.DeviceDetails{Hostname: "gone"}, "Acme", time.Now(), nil)

	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), &info)
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatalf("ARP-absent unreachable device still online after %d misses", offlineMissThreshold)
	}
}
