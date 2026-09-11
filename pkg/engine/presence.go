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

// presenceVerifyEvery is how many presence passes separate two verification
// passes. At the default 10s cadence that is roughly every 70s, so a device
// whose ARP entry lingers after it leaves is retired within a few minutes
// (offlineMissThreshold verification failures) without the patient probe
// running often enough to matter.
const presenceVerifyEvery = 6

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
// This is Tier 1: it is the only tier allowed to declare a device *absent*
// (after offlineMissThreshold misses). Any tier may prove presence. It is
// deliberately not gated on the discovery or enrichment tiers.
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

	// Stamp the network key this pass is accounting against. If discovery or
	// currentNetInfo flips activeNetworkKey mid-pass, discard the apply — the
	// probe targets were selected for a different LAN.
	e.mu.RLock()
	passNetworkKey := e.activeNetworkKey
	e.mu.RUnlock()

	// Phase 1: the ARP table is free Layer-2 evidence, so use it before probing.
	arpStart := time.Now()
	arpConfirmed := make(map[string]string) // IP -> MAC
	arpByMAC := make(map[string]string)     // Normalized MAC -> IP
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
		arpByMAC[NormalizeMAC(row.MAC)] = row.IP
	}

	// Phase 2: decide, per device, what evidence this pass will rest on.
	//
	// An entry in the kernel ARP table is strong Layer-2 evidence: it is there
	// because the device is actually talking on this LAN. It is also *more*
	// reliable than a single active probe, because power-saving devices
	// duty-cycle their radio and answer ICMP only intermittently — measured on
	// a sleeping iPad, the quick probe hit 0/20 while the device was plainly
	// present in ARP and answering 60% of patient pings. Probing every device
	// every pass produced 3-miss offline flips every ~35s, then an immediate
	// re-online: constant false churn.
	//
	// So: ARP vouching keeps a device online without a probe. Devices ARP does
	// *not* vouch for are probed every pass, which is where fast departure
	// detection comes from.
	//
	// Verification passes exist to keep the ARP evidence honest, and they judge
	// by ARP rather than by the probe reply. A probe reply cannot be the
	// arbiter of departure: a Nintendo Switch in standby and a sleeping iPad
	// both answer no ICMP and open no ports, yet are demonstrably present —
	// their ARP entries stay resolved under repeated probing while 230 of the
	// 261 entries on the same LAN sit at `(incomplete)`. Requiring a reply
	// retired exactly the devices ARP-first was added to keep.
	//
	// What the verification probe is really for is provocation: macOS
	// revalidates a link-layer entry roughly every arp_llreach_base seconds
	// (120 here) but only when something uses it, and ARP-vouched devices are
	// otherwise never touched. The probe forces that use; the post-probe ARP
	// re-read is the verdict. A departed device fails revalidation, drops to
	// `(incomplete)`, and is then retired on the normal miss threshold.
	verifyPass := e.nextPresencePass()%presenceVerifyEvery == 0

	type target struct {
		id, ip string
		verify bool // use the patient probe; a miss counts even though ARP vouches
	}
	var (
		targets   []target
		arpHits   []target
		seenByARP = make(map[string]bool)
	)
	e.mu.RLock()
	for _, d := range e.devices {
		if !e.deviceVisibleLocked(d) {
			continue
		}
		normMAC := NormalizeMAC(d.MAC)

		// Follow the device to a new IP when ARP knows its MAC there.
		ipToProbe := d.IP
		if normMAC != "" {
			if newIP, ok := arpByMAC[normMAC]; ok && newIP != "" {
				ipToProbe = newIP
			}
		}

		arpVouches := false
		if d.IP != "" {
			if mac, ok := arpConfirmed[d.IP]; ok && (normMAC == "" || NormalizeMAC(mac) == normMAC) {
				arpVouches = true
			}
		}
		if !arpVouches && normMAC != "" {
			if newIP, ok := arpByMAC[normMAC]; ok && newIP != "" {
				arpVouches = true
			}
		}

		if arpVouches {
			if verifyPass && ipToProbe != "" {
				targets = append(targets, target{id: d.ID, ip: ipToProbe, verify: true})
				continue
			}
			arpHits = append(arpHits, target{id: d.ID, ip: ipToProbe})
			seenByARP[d.ID] = true
			continue
		}

		if ipToProbe != "" {
			targets = append(targets, target{id: d.ID, ip: ipToProbe})
		}
	}
	e.mu.RUnlock()

	arpTook := time.Since(arpStart)

	// Phase 3: probe the rest concurrently. No lock is held here.
	probeStart := time.Now()
	type hit struct {
		id, ip string
		lat    float64
		ok     bool
		verify bool
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
					results[i] = hit{id: t.id, ip: t.ip, verify: t.verify}
					return
				case sem <- struct{}{}:
				}
				defer func() { <-sem }()
				probe := e.probeIPQuick
				if t.verify {
					probe = e.probeIPVerify
				}
				lat, ok := probe(ctx, t.ip)
				results[i] = hit{id: t.id, ip: t.ip, lat: lat, ok: ok, verify: t.verify}
			}(i, t)
		}
		wg.Wait()

		// If any probed targets did not respond to ICMP/TCP (e.g. stealth mode,
		// firewalled, or sleeping mobile devices), re-read the ARP table.
		// Probing provokes the OS kernel to send an ARP request at Layer 2.
		// Since readARPFresh filters out incomplete, expired, and failed-probe
		// entries, any host verified in postARPConfirmed is alive at Layer 2.
		var hasMisses bool
		for _, r := range results {
			if !r.ok {
				hasMisses = true
				break
			}
		}
		if hasMisses {
			postARPConfirmed := make(map[string]string) // IP -> MAC
			postARPByMAC := make(map[string]string)     // MAC -> IP
			for _, row := range e.readARPFresh(ctx) {
				if row.MAC == "" {
					continue
				}
				if subnet != "" && !ipInCIDR(row.IP, subnet) {
					continue
				}
				if iface != "" && row.Iface != "" && !strings.EqualFold(row.Iface, iface) {
					continue
				}
				postARPConfirmed[row.IP] = row.MAC
				postARPByMAC[NormalizeMAC(row.MAC)] = row.IP
			}
			if len(postARPConfirmed) > 0 {
				e.mu.RLock()
				for i, r := range results {
					if r.ok {
						continue
					}
					d, ok := e.devices[r.id]
					if !ok {
						continue
					}
					normMAC := NormalizeMAC(d.MAC)
					// Check if MAC appeared under a new IP
					if normMAC != "" {
						if newIP, found := postARPByMAC[normMAC]; found && newIP != "" && newIP != r.ip {
							results[i].ip = newIP
							results[i].ok = true
							continue
						}
					}
					if mac, found := postARPConfirmed[r.ip]; found {
						if normMAC == "" || NormalizeMAC(mac) == normMAC {
							results[i].ok = true
							continue
						}
					}
				}
				e.mu.RUnlock()
			}
		}
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
	if passNetworkKey != "" && e.activeNetworkKey != passNetworkKey {
		activeKey := e.activeNetworkKey
		e.mu.Unlock()
		slog.Debug("presence apply discarded: network changed mid-pass",
			"pass_key", passNetworkKey, "active_key", activeKey,
			"probed", len(targets), "arp_hits", len(arpHits))
		e.setLastPresence(res)
		return res
	}
	// fromProbe distinguishes an active probe reply from Layer-2 ARP evidence.
	// Only a reply clears the verification counter: ARP says the kernel has an
	// address mapping, which persists for minutes after a device leaves, so it
	// must not erase the record of the patient probe failing.
	applyHit := func(id, ip string, lat float64, fromProbe bool) {
		d, ok := e.devices[id]
		if !ok {
			return // rekeyed mid-pass; the next tick picks it up
		}
		snap := *d
		wasOff := !d.IsOnline
		e.setOnlineLocked(d, true)
		d.LastSeen = now
		if lat > 0 {
			d.LatencyMs = lat
		}
		if ip != "" {
			d.IP = ip
		}
		e.missCount[id] = 0
		if fromProbe {
			delete(e.verifyMiss, id)
		}
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
		// Layer-2 evidence maintains presence, but it cannot restore a device
		// the patient probe has already proven absent — only a probe success
		// (on the next verification pass) may do that. Without this, a departed
		// device with a lingering ARP entry would oscillate every verify cycle.
		if e.verifyMiss[t.id] >= offlineMissThreshold {
			continue
		}
		applyHit(t.id, t.ip, 0, false)
	}
	for _, r := range results {
		if r.ok {
			applyHit(r.id, r.ip, r.lat, true)
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

		// A verification miss — probed, and still not in ARP afterwards — is
		// counted separately. ARP keeps resetting missCount on the intervening
		// passes, so a shared counter could never accumulate enough
		// verification failures to retire a device whose entry has gone stale.
		counter := e.missCount
		if r.verify {
			counter = e.verifyMiss
		}
		counter[r.id]++
		if counter[r.id] >= offlineMissThreshold && d.IsOnline {
			e.setOnlineLocked(d, false)
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
			e.fireAlert(AlertRuleDeviceOnline, d.ID, fmt.Sprintf("%s came back online", d.DisplayName()))
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
		e.fireAlert(AlertRuleDeviceOffline, d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
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
	return e.readARPWithTTL(ctx, arpCacheTTL)
}

func (e *Engine) readARPFresh(ctx context.Context) []scanner.RawDevice {
	return e.readARPWithTTL(ctx, 0)
}

func (e *Engine) readARPWithTTL(ctx context.Context, ttl time.Duration) []scanner.RawDevice {
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
	devs, err := e.netScanner.ARPTableNumeric(ctx, ttl)
	if err != nil {
		return nil
	}
	return devs
}

// probeIPVerify is the patient probe used on verification passes.
func (e *Engine) probeIPVerify(ctx context.Context, ip string) (float64, bool) {
	if e.verifyFn != nil {
		return e.verifyFn(ctx, ip)
	}
	if e.probeFn != nil {
		return e.probeFn(ctx, ip)
	}
	return scanner.ProbeIPVerify(ctx, ip)
}

// nextPresencePass returns a monotonically increasing pass counter, used to
// space verification passes out across presence ticks.
func (e *Engine) nextPresencePass() uint64 {
	return e.presencePass.Add(1)
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
