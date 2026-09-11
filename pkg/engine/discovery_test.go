package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// discoveryEngine wires an engine whose probes are stubbed so a sweep never
// touches the network. reachable lists the IPs the fake subnet answers on.
func discoveryEngine(t *testing.T, reachable ...string) (*Engine, *memPersist, *network.Info) {
	t.Helper()
	p := newMemPersist()
	eng := New(p)
	info := netInfoFor("192.168.0.0/24", "192.168.0.1")

	live := make(map[string]bool, len(reachable))
	for _, ip := range reachable {
		live[ip] = true
	}
	eng.arpFn = func(ctx context.Context) ([]scanner.RawDevice, error) { return nil, nil }
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		if live[ip] {
			return 1.5, true
		}
		return 0, false
	}
	// Stub the sweep itself; the real one expands the /24 and shells out to ping.
	eng.sweepFn = func(ctx context.Context, subnet, iface string,
		skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
		var out []scanner.RawDevice
		for _, ip := range reachable {
			if _, skipped := skipHits[ip]; skipped {
				continue
			}
			out = append(out, scanner.RawDevice{
				IP: ip, MAC: "AA:BB:CC:00:" + ip[len(ip)-2:] + ":01",
				Iface: iface, IsOnline: true, LatencyMs: 1.5,
			})
		}
		if progress != nil {
			progress(len(reachable), len(reachable))
		}
		return out, nil
	}
	eng.setEnrichTestHooks(
		func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
			return mdns.DeviceDetails{}
		},
		func(mac string) string { return "Stub Vendor" },
	)
	eng.SetActiveNetwork(&info)
	return eng, p, &info
}

func TestDiscoverOnceDoesNotFlipOffline(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.77", MAC: "AA:BB:CC:DD:EE:77", LatencyMs: 1},
		mdns.DeviceDetails{Hostname: "nas"}, "Acme", time.Now(), nil)

	// Presence can reach the device; the sweep cannot see it. This is the case
	// the split has to get right: a host that ignores the sweep's probes but is
	// demonstrably up. A sweep miss is not evidence of absence, because Tier 1
	// checked seconds ago and Tier 2 only runs every few minutes.
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) { return 1.0, true }
	eng.sweepFn = func(ctx context.Context, subnet, iface string,
		skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
		return nil, nil // the sweep finds nothing at all
	}

	for i := 0; i < offlineMissThreshold+2; i++ {
		if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
			t.Fatalf("DiscoverOnce: %v", err)
		}
	}

	dev, ok := eng.GetDevice(id)
	if !ok {
		t.Fatal("device disappeared")
	}
	if !dev.IsOnline {
		t.Fatal("the discovery tier must never mark a device offline")
	}
	eng.mu.RLock()
	misses := eng.missCount[id]
	eng.mu.RUnlock()
	if misses != 0 {
		t.Fatalf("missCount = %d; the discovery tier must not advance the counter", misses)
	}
}

func TestDiscoverOnceLeavesOfflineFlipToPresence(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	id := eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.78", MAC: "AA:BB:CC:DD:EE:78", LatencyMs: 1},
		mdns.DeviceDetails{Hostname: "gone"}, "Acme", time.Now(), nil)

	// Nothing can reach the device. Sweeps alone must not retire it — only the
	// presence tier's debounce may, and only at its own threshold.
	eng.sweepFn = func(ctx context.Context, subnet, iface string,
		skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
		return nil, nil
	}
	// Keep presence data fresh so DiscoverOnce takes the skip-list path rather
	// than running a presence pass inline.
	eng.setLastPresence(PresenceResult{Hits: map[string]float64{}, IDs: map[string]bool{}, At: time.Now()})

	for i := 0; i < offlineMissThreshold+2; i++ {
		if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
			t.Fatalf("DiscoverOnce: %v", err)
		}
		eng.setLastPresence(PresenceResult{Hits: map[string]float64{}, IDs: map[string]bool{}, At: time.Now()})
	}
	if dev, _ := eng.GetDevice(id); !dev.IsOnline {
		t.Fatal("sweeps alone marked a device offline; that is Tier 1's call")
	}

	// Presence, in contrast, does retire it.
	for i := 0; i < offlineMissThreshold; i++ {
		eng.PresenceOnce(context.Background(), info)
	}
	if dev, _ := eng.GetDevice(id); dev.IsOnline {
		t.Fatal("presence should have marked the unreachable device offline")
	}
}

func TestDiscoverOnceEnqueuesNewDevices(t *testing.T) {
	eng, _, info := discoveryEngine(t, "192.168.0.42")

	res, err := eng.DiscoverOnce(context.Background(), info)
	if err != nil {
		t.Fatalf("DiscoverOnce: %v", err)
	}
	if len(res.NewIDs) == 0 {
		t.Fatal("expected the reachable host to be reported as new")
	}
	if res.Enqueued == 0 {
		t.Fatal("a newly discovered device must be queued for enrichment")
	}
	if pending, _ := eng.enrichQ.stats(); pending == 0 {
		t.Fatal("the enrichment queue is empty after discovering a new device")
	}
}

func TestDiscoverOnceUsesPresenceSkipHits(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	eng.upsertDevice(
		scanner.RawDevice{IP: "192.168.0.88", MAC: "AA:BB:CC:DD:EE:88"},
		mdns.DeviceDetails{Hostname: "tv"}, "Acme", time.Now(), nil)

	// A fresh presence pass confirms the device...
	eng.probeFn = func(ctx context.Context, ip string) (float64, bool) {
		return 2.0, ip == "192.168.0.88"
	}
	res := eng.PresenceOnce(context.Background(), info)
	if _, ok := res.Hits["192.168.0.88"]; !ok {
		t.Fatalf("presence did not confirm the device: %v", res.Hits)
	}

	// ...so the sweep must receive it in the skip list rather than re-probe it.
	var gotSkip map[string]float64
	eng.sweepFn = func(ctx context.Context, subnet, iface string,
		skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
		gotSkip = skipHits
		return nil, nil
	}
	if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
		t.Fatalf("DiscoverOnce: %v", err)
	}
	if _, ok := gotSkip["192.168.0.88"]; !ok {
		t.Fatalf("skip list = %v; want the address presence just confirmed", gotSkip)
	}
}

func TestDiscoverOnceBatchPersists(t *testing.T) {
	eng, p, info := discoveryEngine(t, "192.168.0.42", "192.168.0.43", "192.168.0.44")

	beforeSingle, beforeBatch, _ := p.counts()
	if _, err := eng.DiscoverOnce(context.Background(), info); err != nil {
		t.Fatalf("DiscoverOnce: %v", err)
	}
	afterSingle, afterBatch, _ := p.counts()

	if afterBatch-beforeBatch != 1 {
		t.Fatalf("SaveDevices called %d times; want exactly one transaction per sweep",
			afterBatch-beforeBatch)
	}
	// Per-device writes should come only from the new-device path, not from a
	// write-per-device loop at the end of the sweep.
	if afterSingle-beforeSingle > 3 {
		t.Fatalf("SaveDevice called %d times; the sweep should batch", afterSingle-beforeSingle)
	}
}

func TestDiscoverOnceGateIsSingleFlight(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	if !eng.discoveryGate.begin() {
		t.Fatal("gate should have been free")
	}
	defer eng.discoveryGate.end(time.Now())

	res, err := eng.DiscoverOnce(context.Background(), info)
	if err != nil {
		t.Fatalf("a busy gate should not be an error: %v", err)
	}
	if res.SeenIDs != nil {
		t.Fatal("a refused pass should not report sweep results")
	}
}

func TestPerformScanStillEmitsScanComplete(t *testing.T) {
	eng, _, info := discoveryEngine(t, "192.168.0.42")

	var order []string
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		switch evt {
		case "scan_start", "scan_complete":
			order = append(order, evt)
		}
	})

	// The web UI brackets a sweep on scan_start/scan_complete and replaces its
	// inventory wholesale on the latter. That contract must not change.
	if _, err := eng.PerformScan(context.Background(), info); err != nil {
		t.Fatalf("PerformScan: %v", err)
	}
	if len(order) != 2 || order[0] != "scan_start" || order[1] != "scan_complete" {
		t.Fatalf("event order = %v, want [scan_start scan_complete]", order)
	}
}

func TestDiscoverOnceRequiresNetwork(t *testing.T) {
	eng, _, _ := discoveryEngine(t)
	if _, err := eng.DiscoverOnce(context.Background(), nil); err == nil {
		t.Fatal("expected an error with no active network")
	}
}

func TestStartTiersExitsOnContextCancel(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	eng.SetActiveNetwork(info)

	// Keep the cadences long so the loops park on their timers immediately.
	sec := 300
	fast := 300
	if _, err := eng.UpdateSettings(SettingsPatch{
		ScanIntervalSec: &sec, PresenceIntervalSec: &fast,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	presenceDone := make(chan struct{})
	discoveryDone := make(chan struct{})
	go func() { eng.presenceLoop(ctx); close(presenceDone) }()
	go func() { eng.discoveryLoop(ctx); close(discoveryDone) }()

	cancel()
	for name, ch := range map[string]chan struct{}{
		"presenceLoop": presenceDone, "discoveryLoop": discoveryDone,
	} {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not exit on ctx cancellation", name)
		}
	}
}

func TestStartTiersIsIdempotent(t *testing.T) {
	eng, _, info := discoveryEngine(t)
	eng.SetActiveNetwork(info)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng.StartTiers(ctx)
	eng.StartTiers(ctx) // must be a no-op, not a second set of loops
}

func TestTierStatusReportsCadences(t *testing.T) {
	eng, _, _ := discoveryEngine(t)
	st := eng.TierStatus()
	if st.PresenceIntervalSec != 10 {
		t.Errorf("PresenceIntervalSec = %d, want 10", st.PresenceIntervalSec)
	}
	if st.DiscoveryIntervalSec != 300 {
		t.Errorf("DiscoveryIntervalSec = %d, want 300", st.DiscoveryIntervalSec)
	}
	if st.EnrichTTLSec != 43200 {
		t.Errorf("EnrichTTLSec = %d, want 43200", st.EnrichTTLSec)
	}
	if st.PresenceRunning || st.DiscoveryRunning {
		t.Error("no tier should report running before any pass")
	}
}
