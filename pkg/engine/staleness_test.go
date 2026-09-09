package engine

import (
	"fmt"
	"testing"
	"time"
)

func TestNeedsEnrichment(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	identified := Device{
		IP: "192.168.0.10", Hostname: "kitchen-hue", DeviceType: "Smart Home",
		Vendor: "Signify Netherlands B.V.",
	}

	tests := []struct {
		name       string
		dev        Device
		ttl        time.Duration
		wantReason EnrichReason
		wantDue    bool
	}{
		{
			name:    "no IP is never enriched",
			dev:     Device{Hostname: "ghost", LastEnrichedAt: ago(time.Hour)},
			wantDue: false,
		},
		{
			name:       "never fingerprinted is always due",
			dev:        Device{IP: "192.168.0.5"},
			wantReason: EnrichReasonNew,
			wantDue:    true,
		},
		{
			name:       "unnamed is retried after the short TTL",
			dev:        Device{IP: "192.168.0.6", LastEnrichedAt: ago(11 * time.Minute)},
			wantReason: EnrichReasonUnnamed,
			wantDue:    true,
		},
		{
			name:       "unnamed inside the short TTL waits",
			dev:        Device{IP: "192.168.0.6", LastEnrichedAt: ago(2 * time.Minute)},
			wantReason: EnrichReasonUnnamed,
			wantDue:    false,
		},
		{
			name: "a custom name counts as named",
			dev: Device{
				IP: "192.168.0.7", CustomName: "Jared's desk lamp",
				DeviceType: "Smart Home", Vendor: "TP-Link",
				LastEnrichedAt: ago(11 * time.Minute),
			},
			wantReason: EnrichReasonStale,
			wantDue:    false,
		},
		{
			name: "named but untyped uses the partial TTL",
			dev: Device{
				IP: "192.168.0.8", Hostname: "printer", Vendor: "Brother",
				LastEnrichedAt: ago(90 * time.Minute),
			},
			wantReason: EnrichReasonUntyped,
			wantDue:    true,
		},
		{
			name: "placeholder vendors do not count as identity",
			dev: Device{
				IP: "192.168.0.9", Hostname: "thing", DeviceType: "Unknown",
				Vendor: "Unknown Vendor", LastEnrichedAt: ago(90 * time.Minute),
			},
			wantReason: EnrichReasonUntyped,
			wantDue:    true,
		},
		{
			name:       "fully identified and fresh is not due",
			dev:        withEnriched(identified, ago(time.Hour)),
			ttl:        12 * time.Hour,
			wantReason: EnrichReasonStale,
			wantDue:    false,
		},
		{
			name:       "fully identified past its TTL is due",
			dev:        withEnriched(identified, ago(13*time.Hour)),
			ttl:        12 * time.Hour,
			wantReason: EnrichReasonStale,
			wantDue:    true,
		},
		{
			name:       "a shorter configured TTL is honoured",
			dev:        withEnriched(identified, ago(2*time.Hour)),
			ttl:        time.Hour,
			wantReason: EnrichReasonStale,
			wantDue:    true,
		},
		{
			name: "the failure backoff suppresses an otherwise-due device",
			dev: Device{
				IP: "192.168.0.11", LastEnrichedAt: ago(30 * time.Minute),
				EnrichFailures: 4, // 5m << 3 = 40m
			},
			wantDue: false,
		},
		{
			name: "the failure backoff expires",
			dev: Device{
				IP: "192.168.0.11", LastEnrichedAt: ago(50 * time.Minute),
				EnrichFailures: 4,
			},
			wantReason: EnrichReasonUnnamed,
			wantDue:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, due := needsEnrichment(tc.dev, now, tc.ttl)
			if due != tc.wantDue {
				t.Fatalf("due = %v, want %v (reason %q)", due, tc.wantDue, reason)
			}
			if tc.wantReason != "" && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func withEnriched(d Device, at time.Time) Device {
	d.LastEnrichedAt = at
	return d
}

func TestNeedsEnrichmentIsPure(t *testing.T) {
	now := time.Now()
	d := Device{
		IP: "192.168.0.5", Hostname: "x", DeviceType: "y", Vendor: "z",
		Services: []string{"HTTP"}, LastEnrichedAt: now.Add(-time.Hour),
	}
	before := fmt.Sprintf("%+v", d)
	needsEnrichment(d, now, time.Hour)
	if got := fmt.Sprintf("%+v", d); got != before {
		t.Fatalf("needsEnrichment mutated its argument:\n before %s\n after  %s", before, got)
	}
}

func TestEnrichReasonPriorityOrdering(t *testing.T) {
	if EnrichReasonManual.priority() >= EnrichReasonNew.priority() {
		t.Fatal("manual must outrank new")
	}
	if EnrichReasonNew.priority() >= EnrichReasonStale.priority() {
		t.Fatal("new must outrank stale")
	}
	for _, r := range []EnrichReason{EnrichReasonWoke, EnrichReasonUnnamed, EnrichReasonUntyped} {
		if r.priority() != EnrichReasonNew.priority() {
			t.Fatalf("%q should share the new/woke band", r)
		}
	}
}

func TestEnrichBackoffGrowsAndCaps(t *testing.T) {
	if got := enrichBackoff(0); got != 0 {
		t.Fatalf("no failures: got %v, want 0", got)
	}
	if got := enrichBackoff(1); got != enrichFailBase {
		t.Fatalf("one failure: got %v, want %v", got, enrichFailBase)
	}
	if enrichBackoff(3) <= enrichBackoff(2) {
		t.Fatal("backoff must grow with consecutive failures")
	}
	for _, n := range []int{12, 40, 1 << 20} {
		if got := enrichBackoff(n); got != enrichFailCap {
			t.Fatalf("enrichBackoff(%d) = %v, want the %v cap", n, got, enrichFailCap)
		}
	}
}

func TestEnrichTTLTiers(t *testing.T) {
	cfg := 6 * time.Hour
	unnamed := Device{IP: "1.2.3.4"}
	partial := Device{IP: "1.2.3.4", Hostname: "a"}
	full := Device{IP: "1.2.3.4", Hostname: "a", DeviceType: "b", Vendor: "c"}

	if got := enrichTTL(unnamed, cfg); got != enrichTTLUnnamed {
		t.Fatalf("unnamed: got %v, want %v", got, enrichTTLUnnamed)
	}
	if got := enrichTTL(partial, cfg); got != enrichTTLPartial {
		t.Fatalf("partial: got %v, want %v", got, enrichTTLPartial)
	}
	if got := enrichTTL(full, cfg); got != cfg {
		t.Fatalf("identified: got %v, want the configured %v", got, cfg)
	}
	if got := enrichTTL(full, 0); got != enrichTTLIdentified {
		t.Fatalf("unset TTL should fall back to %v, got %v", enrichTTLIdentified, got)
	}
}

func TestClampInterval(t *testing.T) {
	tests := []struct{ v, min, max, def, want int }{
		{0, 60, 86400, 300, 300},        // unset -> default
		{-5, 60, 86400, 300, 300},       // negative -> default
		{30, 60, 86400, 300, 60},        // below min -> min
		{999999, 60, 86400, 300, 86400}, // above max -> max
		{600, 60, 86400, 300, 600},      // in range -> unchanged
	}
	for _, tc := range tests {
		if got := clampInterval(tc.v, tc.min, tc.max, tc.def); got != tc.want {
			t.Errorf("clampInterval(%d,%d,%d,%d) = %d, want %d",
				tc.v, tc.min, tc.max, tc.def, got, tc.want)
		}
	}
}

func TestLoadFromStoreSeedsLastEnriched(t *testing.T) {
	identified := Device{
		ID: "AA:BB:CC:DD:EE:01", IP: "192.168.0.11", MAC: "AA:BB:CC:DD:EE:01",
		Hostname: "kitchen-hue", DeviceType: "Smart Home", Vendor: "Signify",
		LastSeen: time.Now().Add(-2 * time.Hour),
	}
	bare := Device{
		ID: "AA:BB:CC:DD:EE:02", IP: "192.168.0.12", MAC: "AA:BB:CC:DD:EE:02",
		LastSeen: time.Now().Add(-2 * time.Hour),
	}
	eng := New(newMemPersist(identified, bare))

	got, ok := eng.GetDevice(identified.ID)
	if !ok {
		t.Fatal("identified device did not load")
	}
	if !got.LastEnrichedAt.Equal(identified.LastSeen) {
		t.Fatalf("LastEnrichedAt = %v, want the seeded LastSeen %v",
			got.LastEnrichedAt, identified.LastSeen)
	}
	if _, due := needsEnrichment(got, time.Now(), 12*time.Hour); due {
		t.Fatal("an already-identified pre-upgrade device should not be immediately due")
	}

	// A device that was never identified must still qualify, so upgrading does
	// not silently strand it without a name.
	gotBare, ok := eng.GetDevice(bare.ID)
	if !ok {
		t.Fatal("bare device did not load")
	}
	if !gotBare.LastEnrichedAt.IsZero() {
		t.Fatalf("unidentified device should keep a zero LastEnrichedAt, got %v", gotBare.LastEnrichedAt)
	}
	reason, due := needsEnrichment(gotBare, time.Now(), 12*time.Hour)
	if !due || reason != EnrichReasonNew {
		t.Fatalf("bare device: reason=%q due=%v, want new/true", reason, due)
	}
}

func TestLoadSettingsMigratesLegacyScanInterval(t *testing.T) {
	p := newMemPersist()
	// The pre-tier default that databases in the wild actually hold.
	_ = p.SetSettings(Settings{ScanIntervalSec: 30, MonitorIntervalSec: 10})

	eng := New(p)
	if got := eng.GetSettings().ScanIntervalSec; got != DefaultSettings().ScanIntervalSec {
		t.Fatalf("ScanIntervalSec = %d, want it migrated to %d",
			got, DefaultSettings().ScanIntervalSec)
	}
	if got := eng.discoveryInterval(); got != 300*time.Second {
		t.Fatalf("discoveryInterval = %v, want 5m", got)
	}
	if stored, _ := p.GetSettings(); stored.ScanIntervalSec != DefaultSettings().ScanIntervalSec {
		t.Fatalf("migration was not persisted: stored %d", stored.ScanIntervalSec)
	}
}

func TestSettingsAccessorsClamp(t *testing.T) {
	eng := New(nil)
	if _, err := eng.UpdateSettings(SettingsPatch{
		ScanIntervalSec:    ptr(5),      // below the 60s floor
		MonitorIntervalSec: ptr(100000), // above the 300s ceiling
		EnrichTTLSec:       ptr(1),      // below the 60s floor
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if got := eng.discoveryInterval(); got != discoveryIntervalMin*time.Second {
		t.Errorf("discoveryInterval = %v, want the %ds floor", got, discoveryIntervalMin)
	}
	if got := eng.presenceInterval(); got != presenceIntervalMax*time.Second {
		t.Errorf("presenceInterval = %v, want the %ds ceiling", got, presenceIntervalMax)
	}
	if got := eng.enrichTTL(); got != enrichTTLMin*time.Second {
		t.Errorf("enrichTTL = %v, want the %ds floor", got, enrichTTLMin)
	}
}

func ptr[T any](v T) *T { return &v }
