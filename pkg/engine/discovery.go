package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/oui"
	"github.com/jaredwarren/Gofing/pkg/probes"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// DiscoveryResult summarizes one full-subnet sweep.
type DiscoveryResult struct {
	Devices  []Device
	NewIDs   []string
	SeenIDs  map[string]bool
	Enqueued int
	Duration time.Duration
}

// DiscoverOnce sweeps the subnet looking for addresses that are not yet in
// inventory.
//
// This is Tier 2, and it is deliberately narrow. It performs no active
// fingerprinting — identity belongs to Tier 3, which can afford the ~1.2s of
// reverse DNS per host because it runs a handful of times an hour instead of
// for every device every 30 seconds. It also never marks a device offline:
// presence belongs to Tier 1, which probed every known host seconds ago, so a
// sweep miss here is not evidence of absence.
func (e *Engine) DiscoverOnce(ctx context.Context, netInfo *network.Info) (DiscoveryResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if netInfo == nil {
		return DiscoveryResult{}, fmt.Errorf("no active network")
	}
	if !e.discoveryGate.begin() {
		// A sweep is already running; report the current view rather than
		// queueing a second pass over the same subnet.
		return DiscoveryResult{Devices: e.GetDevices()}, nil
	}
	passStart := time.Now()
	defer e.discoveryGate.end(passStart)

	e.emitEvent("scan_start", map[string]string{
		"subnet":      netInfo.SubnetCIDR,
		"ssid":        netInfo.SSID,
		"network_key": NetworkKeyFromInfo(netInfo),
	})

	e.mu.Lock()
	prevKey := e.activeNetworkKey
	e.setActiveNetworkLocked(netInfo)
	migrated, deleted := e.reconcileScopedIDsLocked()
	netChanged := prevKey != "" && prevKey != e.activeNetworkKey
	e.mu.Unlock()
	for _, id := range deleted {
		e.deletePersisted(id)
	}
	e.persistDevices(migrated)
	if netChanged {
		e.emitEvent("network_changed", map[string]interface{}{
			"network_key": NetworkKeyFromInfo(netInfo),
			"ssid":        netInfo.SSID,
			"subnet":      netInfo.SubnetCIDR,
			"devices":     e.GetDevices(),
		})
	}
	e.listenMDNS(netInfo.InterfaceName)

	// Ask the network to identify itself before sweeping. Both are fire-and-
	// forget: the mDNS answers land in the listener's cache and are collected
	// by applyCachedHostnames at the end of this pass, and the SSDP responders
	// feed the enrichment queue. Neither blocks the sweep.
	e.browseServices(ctx, netInfo.InterfaceName)
	go e.discoverSSDP(ctx, netInfo.IP)

	// Reuse Tier 1's most recent confirmations as the sweep's skip list. When
	// presence has not run yet — a cold start, or a just-changed network — fall
	// back to running one pass inline so the presence-first optimization holds.
	skipHits := e.lastPresenceHits(2 * e.presenceInterval())
	if skipHits == nil {
		skipHits = e.PresenceOnce(ctx, netInfo).Hits
	}

	rawDevices, err := e.sweepSubnet(ctx, netInfo.SubnetCIDR, netInfo.InterfaceName, skipHits,
		func(current, total int) {
			e.emitEvent("scan_progress", map[string]int{
				"scanned": current,
				"total":   total,
			})
		})
	if err != nil {
		e.emitEvent("scan_error", err.Error())
		return DiscoveryResult{}, err
	}

	now := time.Now()
	wasOnline := make(map[string]bool)
	e.mu.Lock()
	for id, dev := range e.devices {
		wasOnline[id] = dev.IsOnline
	}
	knownIDs := make(map[string]bool, len(e.devices))
	for id := range e.devices {
		knownIDs[id] = true
	}
	e.mu.Unlock()

	seenIDs := make(map[string]bool, len(rawDevices))
	var newIDs []string

	// Every source consulted here is free: the mDNS listener cache, the name
	// macOS already had in `arp -a`, this machine's own computer name, and the
	// embedded OUI table. With no I/O left in the loop body there is nothing to
	// parallelize, so the eight-worker pool this replaced is simply gone.
	for _, raw := range rawDevices {
		var details mdns.DeviceDetails
		vendor := oui.LookupVendorLocal(raw.MAC)

		switch {
		case raw.IP != "" && raw.IP == netInfo.GatewayIP:
			details = mdns.GatewayDetails(vendor)
		default:
			name, src := "", mdns.NameSourceNone
			if e.mdnsResolver != nil {
				name, src = e.mdnsResolver.CachedName(raw.IP)
			}
			if h := mdns.SanitizeHostname(raw.Hostname); h != "" {
				name, src = mdns.PreferHostname(name, src, h, mdns.NameSourceARP)
			}
			if (name == "" || isGenericHostname(name)) && e.netScanner != nil {
				if arpH := e.netScanner.ARPHostname(raw.IP); arpH != "" {
					if h := mdns.SanitizeHostname(arpH); h != "" {
						name, src = mdns.PreferHostname(name, src, h, mdns.NameSourceARP)
					}
				}
			}
			isHost := raw.IP == netInfo.IP ||
				(raw.MAC != "" && netInfo.MAC != "" && NormalizeMAC(raw.MAC) == NormalizeMAC(netInfo.MAC))
			if isHost && netInfo.ComputerName != "" {
				name, src = mdns.PreferHostname(name, src, netInfo.ComputerName, mdns.NameSourceHost)
			}
			details.Hostname, details.NameSource = name, src
		}

		id := e.upsertDeviceOpts(raw, details, vendor, now, wasOnline,
			upsertOpts{
				Persist: false, EmitFound: true, EmitUpdate: true,
				// The sweep already requires an ARP entry, so this is belt and
				// braces — but it is the invariant that keeps a probe artifact
				// from ever becoming a permanent inventory row.
				RequireMACForNew: true,
			})
		if id == "" {
			continue
		}
		seenIDs[id] = true
		if !knownIDs[id] {
			newIDs = append(newIDs, id)
		}
	}

	// Names learned by the multicast listener while the sweep was running.
	e.applyCachedHostnames()

	// Snapshot once, then batch-persist in a single transaction instead of one
	// write per device.
	snapshot := e.snapshotSeen(seenIDs)
	e.persistDevices(snapshot)

	// Hand identity work to Tier 3. New devices go first so a freshly
	// discovered host is named within a second or two of appearing.
	enqueued := 0
	for _, d := range snapshot {
		if !knownIDs[d.ID] {
			if e.enqueueIfStale(d, now) {
				enqueued++
			}
		}
	}
	for _, d := range snapshot {
		if knownIDs[d.ID] {
			if e.enqueueIfStale(d, now) {
				enqueued++
			}
		}
	}

	finalList := e.GetDevices()
	e.emitEvent("scan_complete", map[string]interface{}{
		"total_devices": len(finalList),
		"devices":       finalList,
		"network_key":   NetworkKeyFromInfo(netInfo),
		"timestamp":     now.Format(time.RFC3339),
	})

	return DiscoveryResult{
		Devices:  finalList,
		NewIDs:   newIDs,
		SeenIDs:  seenIDs,
		Enqueued: enqueued,
		Duration: time.Since(passStart),
	}, nil
}

// sweepSubnet runs the ping sweep, through the test seam when set.
func (e *Engine) sweepSubnet(ctx context.Context, subnetCIDR, iface string,
	skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error) {
	e.mu.RLock()
	fn := e.sweepFn
	e.mu.RUnlock()
	if fn != nil {
		return fn(ctx, subnetCIDR, iface, skipHits, progress)
	}
	return e.netScanner.PerformScan(ctx, subnetCIDR, iface, skipHits, progress)
}

// browseServices actively asks which hosts offer well-known services. The
// always-on listener only hears a device that chooses to announce itself, which
// an idle already-associated device may never do.
func (e *Engine) browseServices(ctx context.Context, iface string) {
	if e.mdnsResolver == nil || iface == "" {
		return
	}
	if err := e.mdnsResolver.Browse(ctx, iface, nil); err != nil {
		slog.Debug("mDNS service browse failed", "iface", iface, "error", err)
	}
}

// discoverSSDP multicasts one M-SEARCH and queues every responder for
// enrichment, so a device that answers UPnP but nothing else still gets named.
func (e *Engine) discoverSSDP(ctx context.Context, hostIP string) {
	found, err := probes.DiscoverSSDP(ctx, hostIP, 3*time.Second)
	if err != nil {
		slog.Debug("SSDP discovery failed", "error", err)
		return
	}
	if len(found) == 0 {
		return
	}
	queued := 0
	for ip := range found {
		e.mu.RLock()
		d := e.findKnownForPresenceLocked(ip, "")
		var snap Device
		if d != nil {
			snap = *d
		}
		e.mu.RUnlock()
		if d == nil {
			continue // not in inventory; the sweep owns discovery
		}
		if ok, _ := e.RequestEnrichment(snap.ID, EnrichReasonUntyped); ok {
			queued++
		}
	}
	slog.Debug("SSDP discovery complete", "responders", len(found), "queued", queued)
}

// snapshotSeen copies the devices confirmed by a sweep.
func (e *Engine) snapshotSeen(seenIDs map[string]bool) []Device {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Device, 0, len(seenIDs))
	for id := range seenIDs {
		if d, ok := e.devices[id]; ok {
			out = append(out, *d)
		}
	}
	return out
}

// PerformScan runs one discovery sweep now. Retained for POST /api/scan and for
// existing callers; the periodic sweep is driven by discoveryLoop.
func (e *Engine) PerformScan(ctx context.Context, netInfo *network.Info) ([]Device, error) {
	// Re-verify presence for all known inventory first so reconnected hosts are
	// marked online immediately before we sweep the subnet.
	if netInfo != nil {
		_ = e.PresenceOnce(ctx, netInfo)
	}
	res, err := e.DiscoverOnce(ctx, netInfo)
	if err != nil {
		return nil, err
	}
	return res.Devices, nil
}

// applyCachedHostnames upgrades in-memory hostnames from the mDNS listener
// cache, macOS ARP table, and matching inventory.
func (e *Engine) applyCachedHostnames() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range e.devices {
		if d.IP == "" {
			continue
		}
		if e.mdnsResolver != nil {
			if name, src := e.mdnsResolver.CachedName(d.IP); name != "" && !isGenericHostname(name) {
				d.Hostname, d.NameSource = mdns.PreferHostname(d.Hostname, d.NameSource, name, src)
			}
		}
		if (d.Hostname == "" || isGenericHostname(d.Hostname)) && e.netScanner != nil {
			if arpH := e.netScanner.ARPHostname(d.IP); arpH != "" {
				if h := mdns.SanitizeHostname(arpH); h != "" && !isGenericHostname(h) {
					d.Hostname, d.NameSource = mdns.PreferHostname(d.Hostname, d.NameSource, h, mdns.NameSourceARP)
				}
			}
		}
		if d.Hostname == "" || isGenericHostname(d.Hostname) {
			e.adoptDeviceMetadataLocked(d)
			if d.Hostname == "" {
				if bestName, bestSrc := e.findBestNameLocked(d); bestName != "" {
					d.Hostname, d.NameSource = bestName, bestSrc
				}
			}
		}
	}
}
