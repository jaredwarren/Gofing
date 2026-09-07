package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

const knownProbeConcurrency = 16

// probeKnown marks known inventory online from ARP and a quick reachability
// probe, streaming device_updated as each hit arrives. Misses stay as they
// are (offline at launch). Returns confirmed IPs (for skipping the slow sweep)
// and device IDs (so applyMisses does not treat them as absent).
func (e *Engine) probeKnown(ctx context.Context, netInfo *network.Info) (hits map[string]float64, ids map[string]bool) {
	hits = make(map[string]float64)
	ids = make(map[string]bool)
	if ctx == nil {
		ctx = context.Background()
	}

	suppressAlerts := e.beginStartupPresence()
	defer e.finishStartupPresence()

	subnet, iface := "", ""
	if netInfo != nil {
		subnet = netInfo.SubnetCIDR
		iface = strings.TrimSpace(netInfo.InterfaceName)
	}

	now := time.Now()
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
		if ip, id, ok := e.markKnownOnline("", row.IP, row.MAC, 0, now, suppressAlerts); ok {
			hits[ip] = 0
			ids[id] = true
		}
	}

	type target struct {
		id, ip string
	}
	e.mu.RLock()
	var targets []target
	for _, d := range e.devices {
		if !e.deviceVisibleLocked(d) || d.IP == "" || ids[d.ID] {
			continue
		}
		targets = append(targets, target{id: d.ID, ip: d.IP})
	}
	e.mu.RUnlock()
	if len(targets) == 0 {
		return hits, ids
	}

	var mu sync.Mutex
	sem := make(chan struct{}, knownProbeConcurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			lat, ok := e.probeIPQuick(ctx, t.ip)
			if !ok {
				return
			}
			hitNow := time.Now()
			ip, id, ok := e.markKnownOnline(t.id, t.ip, "", lat, hitNow, suppressAlerts)
			if !ok {
				return
			}
			mu.Lock()
			hits[ip] = lat
			ids[id] = true
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return hits, ids
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
	devs, err := e.netScanner.ARPTable(ctx)
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

// markKnownOnline flips a known device online and emits device_updated.
// id, if set, is preferred; otherwise MAC then IP on the active network.
func (e *Engine) markKnownOnline(id, ip, mac string, lat float64, now time.Time, suppressAlerts bool) (hitIP, hitID string, ok bool) {
	e.mu.Lock()
	var d *Device
	if id != "" {
		d = e.devices[id]
	}
	if d == nil {
		d = e.findKnownForPresenceLocked(ip, mac)
	}
	if d == nil || !e.deviceVisibleLocked(d) {
		e.mu.Unlock()
		return "", "", false
	}

	wasOff := !d.IsOnline
	d.IsOnline = true
	d.LastSeen = now
	if lat > 0 {
		d.LatencyMs = lat
	}
	if ip != "" {
		d.IP = ip
	}
	if mac != "" && d.MAC == "" {
		d.MAC = NormalizeMAC(mac)
	}
	e.missCount[d.ID] = 0
	out := *d
	e.mu.Unlock()

	e.emitEvent("device_updated", &out)
	if wasOff && !suppressAlerts {
		e.recordEvent("online", out.ID, fmt.Sprintf("%s is online", out.DisplayName()))
		e.fireAlert("device_online", out.ID, fmt.Sprintf("%s came back online", out.DisplayName()))
	}
	return out.IP, out.ID, true
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
