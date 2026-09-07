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
	id := seedOfflineDevice(eng, "192.168.0.20", "AA:BB:CC:DD:EE:20", "tv")
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 0, false }

	_, _ = eng.probeKnown(context.Background(), nil)
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
	_, ids := eng.probeKnown(context.Background(), nil)
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
