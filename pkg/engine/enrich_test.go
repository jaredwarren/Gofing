package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func job(id string, reason EnrichReason) enrichJob {
	return enrichJob{DeviceID: id, IP: "192.168.0.9", Reason: reason, Queued: time.Now()}
}

func TestEnrichQueueDedupes(t *testing.T) {
	q := newEnrichQueue()
	if !q.push(job("a", EnrichReasonStale)) {
		t.Fatal("first push should be accepted")
	}
	if q.push(job("a", EnrichReasonStale)) {
		t.Fatal("a duplicate at the same priority should be refused")
	}
	if pending, _ := q.stats(); pending != 1 {
		t.Fatalf("pending = %d, want 1", pending)
	}
}

func TestEnrichQueueUpgradesPriority(t *testing.T) {
	q := newEnrichQueue()
	q.push(job("stale-one", EnrichReasonStale))
	q.push(job("a", EnrichReasonStale))

	// Re-pushing 'a' as manual must move it ahead, not add a second entry.
	if !q.push(job("a", EnrichReasonManual)) {
		t.Fatal("an upgrade to a higher band should be accepted")
	}
	if pending, _ := q.stats(); pending != 2 {
		t.Fatalf("pending = %d, want 2 — the upgrade duplicated the job", pending)
	}

	got, ok := q.pop()
	if !ok {
		t.Fatal("expected a job")
	}
	if got.DeviceID != "a" || got.Reason != EnrichReasonManual {
		t.Fatalf("popped %+v; want the upgraded manual job for 'a'", got)
	}

	// A downgrade must not displace the pending higher-priority job.
	q.done("a")
	q.push(job("b", EnrichReasonManual))
	if q.push(job("b", EnrichReasonStale)) {
		t.Fatal("a downgrade should be refused")
	}
}

func TestEnrichQueueServesBandsInOrder(t *testing.T) {
	q := newEnrichQueue()
	q.push(job("stale", EnrichReasonStale))
	q.push(job("new", EnrichReasonNew))
	q.push(job("manual", EnrichReasonManual))

	var order []string
	for {
		j, ok := q.pop()
		if !ok {
			break
		}
		order = append(order, j.DeviceID)
	}
	want := []string{"manual", "new", "stale"}
	if !sameStrings(order, want) {
		t.Fatalf("served %v, want %v", order, want)
	}
}

func TestEnrichQueueRefusesInflight(t *testing.T) {
	q := newEnrichQueue()
	q.push(job("a", EnrichReasonNew))
	if _, ok := q.pop(); !ok {
		t.Fatal("expected a job")
	}
	if q.push(job("a", EnrichReasonManual)) {
		t.Fatal("a device already in flight should not be re-queued")
	}
	q.done("a")
	if !q.push(job("a", EnrichReasonManual)) {
		t.Fatal("after done() the device should be queueable again")
	}
}

func TestEnrichQueueRekey(t *testing.T) {
	q := newEnrichQueue()
	q.push(job("old", EnrichReasonNew))
	q.rekey("old", "new")

	got, ok := q.pop()
	if !ok {
		t.Fatal("the rekeyed job should still be servable")
	}
	if got.DeviceID != "new" {
		t.Fatalf("DeviceID = %q, want the migrated id", got.DeviceID)
	}
	if got.Reason != EnrichReasonNew {
		t.Fatalf("rekey lost the reason: %q", got.Reason)
	}

	// Rekeying an in-flight device must move the marker, not drop it.
	q2 := newEnrichQueue()
	q2.push(job("old", EnrichReasonNew))
	q2.pop()
	q2.rekey("old", "new")
	if q2.push(job("new", EnrichReasonManual)) {
		t.Fatal("the in-flight marker did not follow the rekey")
	}
}

func TestEnrichQueueOverflowDropsStaleFirst(t *testing.T) {
	q := newEnrichQueue()
	for i := 0; i < enrichQueueMax; i++ {
		q.push(enrichJob{DeviceID: string(rune('A'+i%26)) + string(rune('a'+i/26)),
			Reason: EnrichReasonStale})
	}
	pending, _ := q.stats()
	if pending != enrichQueueMax {
		t.Fatalf("pending = %d, want a full queue of %d", pending, enrichQueueMax)
	}

	// A manual job must still get in, by evicting stale work.
	if !q.push(job("urgent", EnrichReasonManual)) {
		t.Fatal("a manual job should evict stale work to get in")
	}
	if pending, _ = q.stats(); pending != enrichQueueMax {
		t.Fatalf("pending = %d, want the queue to stay at %d", pending, enrichQueueMax)
	}
	first, _ := q.pop()
	if first.DeviceID != "urgent" {
		t.Fatalf("popped %q, want the urgent job first", first.DeviceID)
	}

	// Another stale job cannot displace stale work at its own band.
	q2 := newEnrichQueue()
	for i := 0; i < enrichQueueMax; i++ {
		q2.push(enrichJob{DeviceID: string(rune('A'+i%26)) + string(rune('a'+i/26)),
			Reason: EnrichReasonStale})
	}
	if q2.push(job("another-stale", EnrichReasonStale)) {
		t.Fatal("a stale job should not evict other stale work")
	}
}

func TestEnrichQueueEmptyPop(t *testing.T) {
	q := newEnrichQueue()
	if _, ok := q.pop(); ok {
		t.Fatal("an empty queue should not yield a job")
	}
	if q.push(enrichJob{DeviceID: "", Reason: EnrichReasonNew}) {
		t.Fatal("a job with no device id should be refused")
	}
}

// --- enrichOnce ---

func newEnrichEngine(t *testing.T) (*Engine, *memPersist) {
	t.Helper()
	p := newMemPersist()
	eng := New(p)
	eng.SetActiveNetwork(&network1)
	return eng, p
}

var network1 = netInfoFor("192.168.0.0/24", "192.168.0.1")

func TestEnrichOnceSkipsOfflineDevice(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50"},
		mdns.DeviceDetails{}, "Unknown Vendor", time.Now(), nil)

	// Force it offline, as the presence tier would.
	eng.mu.Lock()
	eng.devices[id].IsOnline = false
	eng.mu.Unlock()

	resolveCalls := 0
	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		resolveCalls++
		return mdns.DeviceDetails{Hostname: "should-not-happen"}
	}, func(mac string) string { return "Acme" })

	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonStale}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("probed an offline device %d times; want 0", resolveCalls)
	}

	got, _ := eng.GetDevice(id)
	if got.LastEnrichedAt.IsZero() {
		t.Fatal("a skipped attempt must still stamp LastEnrichedAt so the TTL advances")
	}
	if got.EnrichFailures != 1 {
		t.Fatalf("EnrichFailures = %d, want 1 so the backoff engages", got.EnrichFailures)
	}
}

func TestEnrichOnceProbesOfflineDeviceWhenManual(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.51", MAC: "AA:BB:CC:DD:EE:51"},
		mdns.DeviceDetails{}, "Unknown Vendor", time.Now(), nil)
	eng.mu.Lock()
	eng.devices[id].IsOnline = false
	eng.mu.Unlock()

	resolveCalls := 0
	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		resolveCalls++
		return mdns.DeviceDetails{Hostname: "asked-for-it", NameSource: mdns.NameSourceDNS}
	}, func(mac string) string { return "Acme" })

	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonManual}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	if resolveCalls != 1 {
		t.Fatalf("a manual request must probe even when offline; calls = %d", resolveCalls)
	}
	got, _ := eng.GetDevice(id)
	if got.Hostname != "asked-for-it" {
		t.Fatalf("Hostname = %q, want the resolved name", got.Hostname)
	}
}

func TestEnrichOnceAppliesDetailsAndStamps(t *testing.T) {
	eng, p := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.52", MAC: "AA:BB:CC:DD:EE:52"},
		mdns.DeviceDetails{}, "", time.Now(), nil)

	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		return mdns.DeviceDetails{
			Hostname:   "kitchen-hue",
			NameSource: mdns.NameSourceDNS,
			DeviceType: "Smart Home",
			Icon:       "bulb",
			Model:      "Hue Bridge",
			Services:   []string{"HTTP"},
		}
	}, func(mac string) string { return "Signify Netherlands B.V." })

	changed, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonNew})
	if err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	if !changed {
		t.Fatal("expected the fingerprint to be reported as changed")
	}

	got, _ := eng.GetDevice(id)
	if got.Hostname != "kitchen-hue" || got.DeviceType != "Smart Home" {
		t.Fatalf("details not applied: %+v", got)
	}
	if got.Vendor != "Signify Netherlands B.V." {
		t.Fatalf("Vendor = %q, want the enriched vendor", got.Vendor)
	}
	if got.LastEnrichedAt.IsZero() {
		t.Fatal("LastEnrichedAt was not stamped")
	}
	if got.EnrichFailures != 0 {
		t.Fatalf("EnrichFailures = %d, want 0 after success", got.EnrichFailures)
	}
	if stored, ok := p.stored(id); !ok || stored.Hostname != "kitchen-hue" {
		t.Fatal("the enriched device was not persisted")
	}
}

func TestEnrichOnceEmitsOnlyWhenMeaningful(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.53", MAC: "AA:BB:CC:DD:EE:53"},
		mdns.DeviceDetails{
			Hostname:   "stable",
			NameSource: mdns.NameSourceDNS,
			DeviceType: "Computer",
			Services:   []string{"SSH"},
		}, "Acme", time.Now(), nil)

	updates := 0
	eng.RegisterEventListener(func(evt string, _ interface{}) {
		if evt == "device_updated" {
			updates++
		}
	})

	// Re-fingerprinting with identical results must not push an SSE frame.
	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		return mdns.DeviceDetails{
			Hostname: "stable", NameSource: mdns.NameSourceDNS,
			DeviceType: "Computer", Services: []string{"SSH"},
		}
	}, func(mac string) string { return "Acme" })

	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonStale}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	if updates != 0 {
		t.Fatalf("emitted %d device_updated frames for an unchanged fingerprint; want 0", updates)
	}

	// A real change must emit. The name has to arrive from a higher-ranked
	// source, since PreferHostname deliberately keeps the incumbent on a tie.
	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		return mdns.DeviceDetails{
			Hostname: "renamed", NameSource: mdns.NameSourceARP,
			DeviceType: "Computer", Services: []string{"SSH"},
		}
	}, func(mac string) string { return "Acme" })

	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonStale}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	if updates != 1 {
		t.Fatalf("emitted %d frames for a renamed device; want 1", updates)
	}
}

func TestEnrichOnceKeepsIncumbentNameOnEqualRank(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.57", MAC: "AA:BB:CC:DD:EE:57"},
		mdns.DeviceDetails{Hostname: "first", NameSource: mdns.NameSourceDNS},
		"Acme", time.Now(), nil)

	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		return mdns.DeviceDetails{Hostname: "second", NameSource: mdns.NameSourceDNS}
	}, func(mac string) string { return "Acme" })

	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonStale}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}
	got, _ := eng.GetDevice(id)
	if got.Hostname != "first" {
		t.Fatalf("Hostname = %q; an equal-ranked source must not displace the incumbent", got.Hostname)
	}
}

func TestEnrichOnceMissingDevice(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: "nope", Reason: EnrichReasonManual}); err == nil {
		t.Fatal("expected an error for an unknown device")
	}
}

func TestEnrichOnceDoesNotWipeKnownFieldsOnEmptyProbe(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.54", MAC: "AA:BB:CC:DD:EE:54"},
		mdns.DeviceDetails{
			Hostname: "known", NameSource: mdns.NameSourceDNS,
			DeviceType: "Computer", Services: []string{"SSH", "HTTP"},
		}, "Acme Corp", time.Now(), nil)

	// A probe that timed out returns nothing. That is not evidence the device
	// lost its name, type, services or vendor.
	eng.SetEnrichTestHooks(
		func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
			return mdns.DeviceDetails{}
		},
		func(mac string) string { return "" },
	)
	if _, err := eng.enrichOnce(context.Background(),
		enrichJob{DeviceID: id, Reason: EnrichReasonStale}); err != nil {
		t.Fatalf("enrichOnce: %v", err)
	}

	got, _ := eng.GetDevice(id)
	if got.Hostname != "known" {
		t.Errorf("Hostname = %q, want it preserved", got.Hostname)
	}
	if got.DeviceType != "Computer" {
		t.Errorf("DeviceType = %q, want it preserved", got.DeviceType)
	}
	if got.Vendor != "Acme Corp" {
		t.Errorf("Vendor = %q, want it preserved", got.Vendor)
	}
	if !sameStrings(got.Services, []string{"SSH", "HTTP"}) {
		t.Errorf("Services = %v, want them preserved", got.Services)
	}
}

func TestRequestEnrichmentContract(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.55", MAC: "AA:BB:CC:DD:EE:55"},
		mdns.DeviceDetails{}, "Unknown Vendor", time.Now(), nil)

	queued, err := eng.RequestEnrichment(id, EnrichReasonManual)
	if err != nil || !queued {
		t.Fatalf("first request: queued=%v err=%v", queued, err)
	}
	queued, err = eng.RequestEnrichment(id, EnrichReasonManual)
	if err != nil {
		t.Fatalf("second request errored: %v", err)
	}
	if queued {
		t.Fatal("a second identical request should report already-queued, not an error")
	}
	if _, err := eng.RequestEnrichment("nope", EnrichReasonManual); err == nil {
		t.Fatal("expected an error for an unknown device")
	}
}

func TestEnrichWorkerExitsOnContextCancel(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		eng.enrichWorker(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("enrichWorker did not exit on ctx cancellation")
	}
}

func TestEnrichWorkerDrainsQueue(t *testing.T) {
	eng, _ := newEnrichEngine(t)
	id := eng.upsertDevice(scanner.RawDevice{IP: "192.168.0.56", MAC: "AA:BB:CC:DD:EE:56"},
		mdns.DeviceDetails{}, "Unknown Vendor", time.Now(), nil)

	resolved := make(chan struct{}, 1)
	eng.SetEnrichTestHooks(func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails {
		select {
		case resolved <- struct{}{}:
		default:
		}
		return mdns.DeviceDetails{Hostname: "worked", NameSource: mdns.NameSourceDNS}
	}, func(mac string) string { return "Acme" })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.runEnrichWorkers(ctx)

	if _, err := eng.RequestEnrichment(id, EnrichReasonManual); err != nil {
		t.Fatalf("RequestEnrichment: %v", err)
	}
	select {
	case <-resolved:
	case <-time.After(3 * time.Second):
		t.Fatal("a queued job was never picked up by a worker")
	}
}
