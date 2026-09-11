package engine

// Gofing scans on three independent tiers, each answering a different question
// at its own cadence:
//
//	Tier 1  presence    which known devices are up?      every ~10s
//	Tier 2  discovery   are there new IPs on the subnet?  every ~5min
//	Tier 3  enrichment  what is this device?             on demand, TTL-driven
//
// They run concurrently and none may block another. Four invariants make that
// safe:
//
//  1. Never hold e.mu across I/O.
//  2. Never emit an event or persist while holding any lock. Collect into a
//     slice, unlock, then loop.
//  3. A device's ID can be rekeyed underneath you (see upsertDevice's remount).
//     Always re-look-up by ID and tolerate a miss.
//  4. If two locks are ever held at once, the order is e.mu then enrichQ.mu.
//     Never the reverse.
//
// Ownership is partitioned so the tiers need no coordination beyond those
// rules:
//
//   - Presence (IsOnline / missCount): any tier may prove a device *present*
//     (a sweep hit or ARP confirmation is positive evidence). Only Tier 1 may
//     declare a device *absent*, and only after offlineMissThreshold consecutive
//     misses. All IsOnline writes go through setOnlineLocked.
//   - Discovery alone sweeps for new hosts.
//   - Enrichment alone writes identity fields (hostname, vendor, type, …).
//
// IsOnline writes are funneled through setOnlineLocked so the asymmetric rule
// stays greppable.

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jaredwarren/Gofing/pkg/network"
)

// tierGate is a single-flight guard for one tier's pass. Passes of different
// tiers overlap freely; a tier never overlaps itself.
//
// This replaces the isScanning / isMonitoring / scanGen trio, which existed to
// stop tiers from running at the same time — exactly the behaviour that made
// presence detection stall for the duration of every scan.
type tierGate struct {
	inflight atomic.Bool
	lastRun  atomic.Int64 // UnixNano of the last completion
	lastDur  atomic.Int64 // nanoseconds
}

// begin claims the gate. false means a pass of this tier is already running.
func (g *tierGate) begin() bool { return g.inflight.CompareAndSwap(false, true) }

// end releases the gate and records the pass duration.
func (g *tierGate) end(started time.Time) {
	if !started.IsZero() {
		g.lastDur.Store(int64(time.Since(started)))
	}
	g.lastRun.Store(time.Now().UnixNano())
	g.inflight.Store(false)
}

func (g *tierGate) running() bool { return g.inflight.Load() }

// lastCompleted returns when this tier last finished a pass, zero if never.
func (g *tierGate) lastCompleted() time.Time {
	ns := g.lastRun.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (g *tierGate) lastDuration() time.Duration { return time.Duration(g.lastDur.Load()) }

// StartTiers launches the presence, discovery and enrichment tiers. It is
// idempotent, and every goroutine it starts exits when ctx is cancelled.
func (e *Engine) StartTiers(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.tiersOnce.Do(func() {
		go e.presenceLoop(ctx)
		go e.discoveryLoop(ctx)
		e.runEnrichWorkers(ctx)
	})
}

// presenceLoop runs Tier 1 on its own cadence, re-reading the interval each
// tick so a settings change takes effect without a restart. The timer is reset
// after each pass rather than ticking, so a slow pass cannot stack up.
func (e *Engine) presenceLoop(ctx context.Context) {
	e.PresenceOnce(ctx, e.currentNetInfo(0))

	timer := time.NewTimer(e.presenceInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			interval := e.presenceInterval()
			passCtx, cancel := context.WithTimeout(ctx, 2*interval)
			e.PresenceOnce(passCtx, e.currentNetInfo(30*time.Second))
			cancel()
			timer.Reset(interval)
		}
	}
}

// discoveryLoop runs Tier 2 on its own cadence, starting with one immediate
// sweep so a fresh launch populates the inventory without waiting a full
// interval.
func (e *Engine) discoveryLoop(ctx context.Context) {
	runOnce := func() {
		info := e.currentNetInfo(0)
		if info == nil {
			slog.Warn("skipping discovery sweep: no active network")
			return
		}
		passCtx, cancel := context.WithTimeout(ctx, discoveryPassBudget)
		defer cancel()
		res, err := e.DiscoverOnce(passCtx, info)
		if err != nil {
			slog.Warn("discovery sweep failed", "error", err)
			return
		}
		slog.Info("discovery sweep complete",
			"devices", len(res.Devices), "new", len(res.NewIDs),
			"queued_for_enrichment", res.Enqueued, "took", res.Duration.Round(time.Millisecond))
	}

	slog.Info("performing initial subnet scan")
	runOnce()

	timer := time.NewTimer(e.discoveryInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			runOnce()
			timer.Reset(e.discoveryInterval())
		}
	}
}

// discoveryPassBudget caps a single sweep. A /24 at the current fan-out takes
// well under a minute; anything approaching this is wedged.
const discoveryPassBudget = 4 * time.Minute

// currentNetInfo returns the cached active network, refreshing it via
// network.GetActiveNetworkInfo when the cache is older than maxAge. maxAge <= 0
// forces a refresh.
//
// The detection shells out to route/networksetup/ipconfig, so the presence tier
// must not do it on every tick — but it does need to notice a Wi-Fi change well
// before the next five-minute sweep. When the refreshed info implies a different
// NetworkKey, this also updates activeNetworkKey (and emits network_changed) so
// deviceVisibleLocked and ARP/subnet filtering stay on the same LAN.
func (e *Engine) currentNetInfo(maxAge time.Duration) *network.Info {
	if maxAge > 0 {
		e.mu.RLock()
		cached, at := e.netInfo, e.netInfoAt
		e.mu.RUnlock()
		if cached != nil && !at.IsZero() && time.Since(at) < maxAge {
			return cached
		}
	}

	info, err := e.detectActiveNetwork()
	if err != nil || info == nil {
		// Fall back to whatever we last knew rather than reporting no network.
		e.mu.RLock()
		cached := e.netInfo
		e.mu.RUnlock()
		if err != nil {
			slog.Debug("active network detection failed; using cached info", "error", err)
		}
		return cached
	}

	e.mu.Lock()
	prevKey := e.activeNetworkKey
	e.setActiveNetworkLocked(info)
	keyChanged := prevKey != e.activeNetworkKey
	var migrated []Device
	var deleted []string
	if keyChanged {
		migrated, deleted = e.reconcileScopedIDsLocked()
	}
	out := e.netInfo
	e.mu.Unlock()

	if keyChanged {
		for _, id := range deleted {
			e.deletePersisted(id)
		}
		e.persistDevices(migrated)
		if prevKey != "" {
			e.emitEvent("network_changed", NetworkChangedEvent{
				NetworkKey: NetworkKeyFromInfo(info),
				SSID:       info.SSID,
				Subnet:     info.SubnetCIDR,
				Devices:    e.GetDevices(),
			})
		}
	}
	return out
}

func (e *Engine) detectActiveNetwork() (*network.Info, error) {
	if e.netDetectFn != nil {
		return e.netDetectFn()
	}
	return network.GetActiveNetworkInfo()
}

// TierStatus is the observable state of the three tiers, surfaced on
// GET /api/devices so a client can tell which tier is behind.
type TierStatus struct {
	PresenceAt      string `json:"presence_at,omitempty"`
	PresenceMs      int64  `json:"presence_ms,omitempty"`
	PresenceRunning bool   `json:"presence_running"`

	DiscoveryAt      string `json:"discovery_at,omitempty"`
	DiscoveryMs      int64  `json:"discovery_ms,omitempty"`
	DiscoveryRunning bool   `json:"discovery_running"`

	EnrichPending  int `json:"enrich_pending"`
	EnrichInflight int `json:"enrich_inflight"`

	PresenceIntervalSec  int `json:"presence_interval_sec"`
	DiscoveryIntervalSec int `json:"discovery_interval_sec"`
	EnrichTTLSec         int `json:"enrich_ttl_sec"`
}

// TierStatus reports each tier's last completion, whether it is running now,
// and the enrichment queue depth.
func (e *Engine) TierStatus() TierStatus {
	pending, inflight := e.enrichQ.stats()
	st := TierStatus{
		PresenceRunning:      e.presenceGate.running(),
		PresenceMs:           e.presenceGate.lastDuration().Milliseconds(),
		DiscoveryRunning:     e.discoveryGate.running(),
		DiscoveryMs:          e.discoveryGate.lastDuration().Milliseconds(),
		EnrichPending:        pending,
		EnrichInflight:       inflight,
		PresenceIntervalSec:  int(e.presenceInterval().Seconds()),
		DiscoveryIntervalSec: int(e.discoveryInterval().Seconds()),
		EnrichTTLSec:         int(e.enrichTTL().Seconds()),
	}
	if at := e.presenceGate.lastCompleted(); !at.IsZero() {
		st.PresenceAt = at.UTC().Format(time.RFC3339)
	}
	if at := e.discoveryGate.lastCompleted(); !at.IsZero() {
		st.DiscoveryAt = at.UTC().Format(time.RFC3339)
	}
	return st
}
