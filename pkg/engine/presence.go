package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// presenceConcurrency bounds how many known hosts are probed at once. Known
// inventory is a few dozen addresses, not a whole subnet, so this can stay well
// below the discovery sweep's fan-out without costing wall time.
const presenceConcurrency = 16

// arpCacheTTL is how long a parsed ARP table may be reused. The kernel table
// does not change meaningfully faster than this, and a pass used to exec arp
// two or three times within a couple of seconds.
const arpCacheTTL = 2 * time.Second

// PresenceResult is the outcome of one Tier-1 pass.
type PresenceResult struct {
	Hits map[string]float64 // IP -> latency ms; feeds the discovery sweep's skip list
	IDs  map[string]bool    // device IDs confirmed present
	At   time.Time
}

// PresenceOnce probes known inventory on the active network and reconciles
// online/offline state.
//
// This is Tier 1: it is the sole owner of Device.IsOnline and missCount, and it
// is deliberately not gated on the discovery or enrichment tiers. Blocking it
// while a full scan ran is what used to leave presence detection dead for two
// thirds of every cycle.
func (e *Engine) PresenceOnce(ctx context.Context, netInfo *network.Info) PresenceResult {
	if ctx == nil {
		ctx = context.Background()
	}
	res := PresenceResult{
		Hits: make(map[string]float64),
		IDs:  make(map[string]bool),
		At:   time.Now(),
	}
	if !e.presenceGate.begin() {
		return res // a pass is already running; its result will be the fresh one
	}
	passStart := time.Now()
	res.At = passStart
	defer e.presenceGate.end(passStart)

	suppressAlerts := e.beginStartupPresence()
	defer e.finishStartupPresence()

	if netInfo == nil {
		netInfo = e.currentNetInfo(0)
	}
	subnet, iface := "", ""
	if netInfo != nil {
		subnet = netInfo.SubnetCIDR
		iface = strings.TrimSpace(netInfo.InterfaceName)
	}

	// Phase 1: the ARP table is free Layer-2 evidence, so use it before probing.
	arpStart := time.Now()
	arpConfirmed := make(map[string]string) // IP -> MAC
	for _, row := range e.readARP(ctx) {
		if row.MAC == "" {
			continue
		}
		if subnet != "" && !ipInCIDR(row.IP, subnet) {
			continue
		}
		if iface != "" && row.Iface != "" && !strings.EqualFold(row.Iface, iface) {
			continue
		}
		arpConfirmed[row.IP] = row.MAC
	}

	// Phase 2: snapshot what to probe. Anything ARP already vouched for is
	// skipped — that check is what keeps a busy LAN off the probe path.
	type target struct {
		id, ip string
	}
	var (
		targets   []target
		arpHits   []target
		seenByARP = make(map[string]bool)
	)
	e.mu.RLock()
	for _, d := range e.devices {
		if !e.deviceVisibleLocked(d) || d.IP == "" {
			continue
		}
		if mac, ok := arpConfirmed[d.IP]; ok {
			if d.MAC == "" || NormalizeMAC(mac) == NormalizeMAC(d.MAC) {
				arpHits = append(arpHits, target{id: d.ID, ip: d.IP})
				seenByARP[d.ID] = true
				continue
			}
		}
		targets = append(targets, target{id: d.ID, ip: d.IP})
	}
	e.mu.RUnlock()

	arpTook := time.Since(arpStart)

	// Phase 3: probe the rest concurrently. No lock is held here.
	probeStart := time.Now()
	type hit struct {
		id, ip string
		lat    float64
		ok     bool
	}
	results := make([]hit, len(targets))
	if len(targets) > 0 {
		sem := make(chan struct{}, presenceConcurrency)
		var wg sync.WaitGroup
		for i, t := range targets {
			wg.Add(1)
			go func(i int, t target) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					results[i] = hit{id: t.id, ip: t.ip}
					return
				case sem <- struct{}{}:
				}
				defer func() { <-sem }()
				lat, ok := e.probeIPQuick(ctx, t.ip)
				results[i] = hit{id: t.id, ip: t.ip, lat: lat, ok: ok}
			}(i, t)
		}
		wg.Wait()
	}

	probeTook := time.Since(probeStart)

	// Phase 4: apply every result under one lock, collecting side effects to
	// run after unlocking.
	applyStart := time.Now()
	now := time.Now()
	var (
		cameOnline  []Device
		wentOffline []Device
		changed     []Device
		before      = make(map[string]Device)
		stale       []Device
	)

	e.mu.Lock()
	applyHit := func(id, ip string, lat float64) {
		d, ok := e.devices[id]
		if !ok {
			return // rekeyed mid-pass; the next tick picks it up
		}
		snap := *d
		wasOff := !d.IsOnline
		d.IsOnline = true
		d.LastSeen = now
		if lat > 0 {
			d.LatencyMs = lat
		}
		if ip != "" {
			d.IP = ip
		}
		e.missCount[id] = 0
		res.Hits[d.IP] = lat
		res.IDs[id] = true
		before[id] = snap
		if wasOff {
			cameOnline = append(cameOnline, *d)
		} else if deviceChangedMeaningfully(snap, *d) {
			changed = append(changed, *d)
		}
	}

	for _, t := range arpHits {
		applyHit(t.id, t.ip, 0)
	}
	for _, r := range results {
		if r.ok {
			applyHit(r.id, r.ip, r.lat)
			continue
		}
		d, ok := e.devices[r.id]
		if !ok {
			continue
		}
		// Another tier — discovery, the mDNS listener, a DHCP import — may have
		// proven this device present after our pass began. Our miss is stale
		// evidence and must not count against it. This is what replaces the old
		// scanGen generation counter: the question is per-device, not global.
		if d.LastSeen.After(passStart) {
			continue
		}
		e.missCount[r.id]++
		if e.missCount[r.id] >= offlineMissThreshold && d.IsOnline {
			d.IsOnline = false
			wentOffline = append(wentOffline, *d)
		}
	}

	// Collect enrichment candidates while we already hold the lock.
	admitted := 0
	for _, d := range e.devices {
		if admitted >= enrichAdmitPerPass {
			break
		}
		if !e.deviceVisibleLocked(d) || !d.IsOnline {
			continue
		}
		stale = append(stale, *d)
		admitted++
	}
	e.mu.Unlock()
	applyTook := time.Since(applyStart)
	sideStart := time.Now()

	// Phase 5: side effects, all outside the lock.
	for i := range cameOnline {
		d := cameOnline[i]
		e.persistDevice(d)
		if !suppressAlerts {
			e.recordEvent("online", d.ID, fmt.Sprintf("%s is online", d.DisplayName()))
			e.fireAlert("device_online", d.ID, fmt.Sprintf("%s came back online", d.DisplayName()))
		}
		e.emitEvent("device_updated", &d)
		// A sleeping device should get named the moment it wakes, which the old
		// every-30s full fingerprint pass provided by accident.
		e.enqueueWoke(d)
	}
	for i := range wentOffline {
		d := wentOffline[i]
		e.persistDevice(d)
		e.recordEvent("offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
		e.emitEvent("device_offline", d)
		e.emitEvent("device_updated", d)
		e.fireAlert("device_offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
	}
	for i := range changed {
		d := changed[i]
		e.emitEvent("device_updated", &d)
	}

	// Steady-state driver for Tier 3: the discovery sweep only runs every few
	// minutes, so presence is what notices an expired fingerprint TTL.
	for _, d := range stale {
		e.enqueueIfStale(d, now)
	}

	e.setLastPresence(res)

	slog.Debug("presence pass complete",
		"took", time.Since(passStart).Round(time.Millisecond),
		"arp", arpTook.Round(time.Millisecond),
		"probe", probeTook.Round(time.Millisecond),
		"apply", applyTook.Round(time.Millisecond),
		"side_effects", time.Since(sideStart).Round(time.Millisecond),
		"arp_confirmed", len(arpHits), "probed", len(targets),
		"online", len(res.IDs), "came_online", len(cameOnline),
		"went_offline", len(wentOffline), "emitted", len(changed))
	return res
}

// probeKnown returns one presence pass's confirmed IPs and device IDs. Retained
// for the discovery sweep's cold-start path and for existing callers.
func (e *Engine) probeKnown(ctx context.Context, netInfo *network.Info) (hits map[string]float64, ids map[string]bool) {
	res := e.PresenceOnce(ctx, netInfo)
	return res.Hits, res.IDs
}

// setLastPresence records the newest presence snapshot for the discovery tier.
func (e *Engine) setLastPresence(res PresenceResult) {
	e.mu.Lock()
	e.lastPresence = res
	e.mu.Unlock()
}

// lastPresenceHits returns the most recent presence hit set if it is fresher
// than maxAge, so the discovery sweep can skip re-probing what Tier 1 just
// confirmed. nil means there is nothing recent enough to trust.
func (e *Engine) lastPresenceHits(maxAge time.Duration) map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.lastPresence.At.IsZero() || time.Since(e.lastPresence.At) > maxAge {
		return nil
	}
	out := make(map[string]float64, len(e.lastPresence.Hits))
	for ip, lat := range e.lastPresence.Hits {
		out[ip] = lat
	}
	return out
}

func (e *Engine) beginStartupPresence() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startupPresence
}

func (e *Engine) finishStartupPresence() {
	e.mu.Lock()
	e.startupPresence = false
	e.mu.Unlock()
}

func (e *Engine) readARP(ctx context.Context) []scanner.RawDevice {
	if e.arpFn != nil {
		devs, err := e.arpFn(ctx)
		if err != nil {
			return nil
		}
		return devs
	}
	if e.netScanner == nil {
		return nil
	}
	devs, err := e.netScanner.ARPTableNumeric(ctx, arpCacheTTL)
	if err != nil {
		return nil
	}
	return devs
}

func (e *Engine) probeIPQuick(ctx context.Context, ip string) (float64, bool) {
	if e.probeFn != nil {
		return e.probeFn(ctx, ip)
	}
	return scanner.ProbeIPQuick(ctx, ip)
}

func (e *Engine) findKnownForPresenceLocked(ip, mac string) *Device {
	normMAC := NormalizeMAC(mac)
	var byIP *Device
	for _, d := range e.devices {
		if !e.deviceVisibleLocked(d) {
			continue
		}
		if normMAC != "" && d.MAC != "" && NormalizeMAC(d.MAC) == normMAC {
			return d
		}
		if ip != "" && d.IP == ip {
			byIP = d
		}
	}
	return byIP
}
