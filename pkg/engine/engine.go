package engine

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/oui"
	"github.com/jaredwarren/Gofing/pkg/ports"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// Device represents an enriched network device.
type Device struct {
	ID                 string              `json:"id"`
	IP                 string              `json:"ip"`
	MAC                string              `json:"mac"`
	PreviousMACs       []string            `json:"previous_macs,omitempty"`
	Vendor             string              `json:"vendor"`
	Hostname           string              `json:"hostname"`
	NameSource         string              `json:"name_source,omitempty"` // mdns.NameSource* — ranked persistence
	CustomName         string              `json:"custom_name,omitempty"`
	Note               string              `json:"note,omitempty"`
	DeviceType         string              `json:"device_type"`
	DeviceTypeOverride string              `json:"device_type_override,omitempty"`
	Icon               string              `json:"icon"`
	Model              string              `json:"model"`
	LatencyMs          float64             `json:"latency_ms"`
	IsOnline           bool                `json:"is_online"`
	IsPrivateMAC       bool                `json:"is_private_mac"`
	FirstSeen          time.Time           `json:"first_seen"`
	LastSeen           time.Time           `json:"last_seen"`
	Services           []string            `json:"services"`
	OpenPorts          []ports.ServicePort `json:"open_ports,omitempty"`
	RiskScore          string              `json:"risk_score,omitempty"` // none|low|medium|high
	RiskFindings       []string            `json:"risk_findings,omitempty"`
}

// DevicePatch is the set of user-editable fields (PATCH /api/devices/{id}).
type DevicePatch struct {
	CustomName         *string `json:"custom_name"`
	Note               *string `json:"note"`
	DeviceTypeOverride *string `json:"device_type_override"`
}

// EventFunc is called when a device is discovered or updated.
type EventFunc func(eventType string, data interface{})

// offlineMissThreshold is how many consecutive scans must miss a device
// before it is marked offline. Absorbs flaky Wi‑Fi / probe timeouts.
const offlineMissThreshold = 3

// Engine coordinates scanning, fingerprinting, and state management.
type Engine struct {
	mu              sync.RWMutex
	devices         map[string]*Device // keyed by stable Device.ID
	missCount       map[string]int     // consecutive scan misses per device ID
	portScanMu      sync.Mutex
	portScanInflight map[string]bool
	netScanner      *scanner.Scanner
	mdnsResolver    *mdns.Resolver
	listeners       []EventFunc
	isScanning      bool
	persist         Persistence
}

// New returns an initialized Engine. persist may be nil (in-memory only).
func New(persist Persistence) *Engine {
	e := &Engine{
		devices:          make(map[string]*Device),
		missCount:        make(map[string]int),
		portScanInflight: make(map[string]bool),
		netScanner:       scanner.New(),
		mdnsResolver:     mdns.New(),
		persist:          persist,
	}
	e.loadFromStore()
	return e
}

func (e *Engine) loadFromStore() {
	if e.persist == nil {
		return
	}
	loaded, err := e.persist.LoadDevices()
	if err != nil || len(loaded) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range loaded {
		d := loaded[i]
		d.IsOnline = false
		if d.ID == "" {
			d.ID = DeviceID(d.MAC, d.IP)
		}
		d.Hostname = mdns.SanitizeHostname(d.Hostname)
		if d.Hostname == "" {
			d.NameSource = mdns.NameSourceNone
		}
		cp := d
		e.devices[cp.ID] = &cp
	}
}

// RegisterEventListener adds a subscriber for scan events.
func (e *Engine) RegisterEventListener(fn EventFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listeners = append(e.listeners, fn)
}

func (e *Engine) emitEvent(eventType string, data interface{}) {
	e.mu.RLock()
	listeners := make([]EventFunc, len(e.listeners))
	copy(listeners, e.listeners)
	e.mu.RUnlock()

	for _, l := range listeners {
		l(eventType, data)
	}
}

func (e *Engine) persistDevice(d Device) {
	if e.persist == nil {
		return
	}
	_ = e.persist.SaveDevice(d)
}

func (e *Engine) recordEvent(typ, deviceID, message string) {
	if e.persist == nil {
		return
	}
	_ = e.persist.AppendEvent(Event{
		Type:      typ,
		DeviceID:  deviceID,
		Message:   message,
		Timestamp: time.Now(),
	})
}

// GetDevices returns all tracked devices sorted by IP address.
func (e *Engine) GetDevices() []Device {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var list []Device
	for _, dev := range e.devices {
		list = append(list, *dev)
	}

	sort.Slice(list, func(i, j int) bool {
		return compareIPs(list[i].IP, list[j].IP)
	})

	return list
}

// GetDevice returns a device by stable ID.
func (e *Engine) GetDevice(id string) (Device, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	d, ok := e.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// PatchDevice applies user-editable field updates and persists them.
func (e *Engine) PatchDevice(id string, patch DevicePatch) (Device, error) {
	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return Device{}, fmt.Errorf("device not found")
	}
	if patch.CustomName != nil {
		d.CustomName = *patch.CustomName
	}
	if patch.Note != nil {
		d.Note = *patch.Note
	}
	if patch.DeviceTypeOverride != nil {
		d.DeviceTypeOverride = *patch.DeviceTypeOverride
	}
	out := *d
	e.mu.Unlock()

	e.persistDevice(out)
	e.emitEvent("device_updated", &out)
	return out, nil
}

// NameResolveResult is returned by ResolveDeviceName.
type NameResolveResult struct {
	Device     Device                `json:"device"`
	Found      bool                  `json:"found"`
	Changed    bool                  `json:"changed"`
	Hostname   string                `json:"hostname,omitempty"`
	NameSource string                `json:"name_source,omitempty"`
	Candidates []mdns.NameCandidate  `json:"candidates,omitempty"`
	Message    string                `json:"message,omitempty"`
}

// ResolveDeviceName force-fetches Bonjour/DNS names for a device and persists
// an upgrade via ranked PreferHostname.
func (e *Engine) ResolveDeviceName(id string) (NameResolveResult, error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return NameResolveResult{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return NameResolveResult{Device: dev, Message: "device has no IP"}, nil
	}

	// Nudge the host so macOS may refresh ARP / mDNS cache entries.
	warmHostFn(dev.IP)

	var candidates []mdns.NameCandidate
	bestName, bestSrc := "", mdns.NameSourceNone

	consider := func(name, source string) {
		name = mdns.SanitizeHostname(name)
		if name == "" {
			return
		}
		candidates = append(candidates, mdns.NameCandidate{Hostname: name, Source: source})
		bestName, bestSrc = mdns.PreferHostname(bestName, bestSrc, name, source)
	}

	if arpName := e.netScanner.ARPHostname(dev.IP); arpName != "" {
		consider(arpName, mdns.NameSourceARP)
	}

	deep := deepLookupFn(e.mdnsResolver, dev.IP)
	for _, c := range deep.Candidates {
		consider(c.Hostname, c.Source)
	}
	if deep.Hostname != "" {
		consider(deep.Hostname, deep.NameSource)
	}

	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return NameResolveResult{}, fmt.Errorf("device not found")
	}
	before := d.Hostname
	beforeSrc := d.NameSource
	if bestName != "" {
		d.Hostname, d.NameSource = mdns.PreferHostname(d.Hostname, d.NameSource, bestName, bestSrc)
	}
	changed := d.Hostname != before || d.NameSource != beforeSrc
	out := *d
	e.mu.Unlock()

	if changed {
		e.persistDevice(out)
		e.recordEvent("name_resolved", out.ID, fmt.Sprintf("Name resolved to %s", out.Hostname))
		e.emitEvent("device_updated", &out)
	}

	res := NameResolveResult{
		Device:     out,
		Found:      bestName != "" || out.Hostname != "",
		Changed:    changed,
		Hostname:   out.Hostname,
		NameSource: out.NameSource,
		Candidates: candidates,
	}
	if !res.Found {
		res.Message = "No Bonjour/DNS name found — device may be offline or not advertising"
	} else if !changed {
		res.Message = "Name unchanged (already best known source)"
	}
	return res, nil
}

// LookupDeviceNames returns reverse-DNS / Bonjour candidates without mutating state.
func (e *Engine) LookupDeviceNames(id string) (mdns.LookupResult, error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return mdns.LookupResult{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return mdns.LookupResult{}, nil
	}
	warmHostFn(dev.IP)
	res := deepLookupFn(e.mdnsResolver, dev.IP)
	if arpName := e.netScanner.ARPHostname(dev.IP); arpName != "" {
		if h := mdns.SanitizeHostname(arpName); h != "" {
			res.Candidates = append([]mdns.NameCandidate{{Hostname: h, Source: mdns.NameSourceARP}}, res.Candidates...)
			res.Hostname, res.NameSource = mdns.PreferHostname(res.Hostname, res.NameSource, h, mdns.NameSourceARP)
		}
	}
	return res, nil
}

func warmHost(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "500", ip)
	_ = cmd.Run()
}

// Test hooks — overridden in unit tests to avoid real network I/O.
var (
	warmHostFn = warmHost
	deepLookupFn = func(r *mdns.Resolver, ip string) mdns.LookupResult {
		return r.LookupHostnameDeep(ip)
	}
)

func (e *Engine) backgroundNameResolve(id string) {
	select {
	case nameResolveSem <- struct{}{}:
		defer func() { <-nameResolveSem }()
	default:
		// Already resolving other devices; scan path / manual button can retry.
		return
	}
	_, _ = e.ResolveDeviceName(id)
}

// Limits concurrent background deep lookups during discovery.
var nameResolveSem = make(chan struct{}, 2)

// ErrPortScanInProgress is returned when a port scan for the device is already running.
var ErrPortScanInProgress = fmt.Errorf("port scan already in progress")

func (e *Engine) tryBeginPortScan(id string) bool {
	e.portScanMu.Lock()
	defer e.portScanMu.Unlock()
	if e.portScanInflight[id] {
		return false
	}
	e.portScanInflight[id] = true
	return true
}

func (e *Engine) endPortScan(id string) {
	e.portScanMu.Lock()
	defer e.portScanMu.Unlock()
	delete(e.portScanInflight, id)
}

// TryStartPortScan validates and launches an async port scan. started=false means
// one is already in flight for this device (not an error).
func (e *Engine) TryStartPortScan(id, mode string) (started bool, err error) {
	if _, ok := e.GetDevice(id); !ok {
		return false, fmt.Errorf("device not found")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "common"
	}
	if mode != "common" && mode != "deep" {
		return false, fmt.Errorf("invalid mode %q (use common or deep)", mode)
	}
	if !e.tryBeginPortScan(id) {
		return false, nil
	}
	go func() {
		defer e.endPortScan(id)
		if _, err := e.runPortScan(id, mode); err != nil {
			log.Printf("port scan %s (%s): %v", id, mode, err)
			e.emitEvent("portscan_error", map[string]interface{}{
				"id":    id,
				"mode":  mode,
				"error": err.Error(),
			})
		}
	}()
	return true, nil
}

// ScanDevicePorts probes a device for open ports and persists the result.
// mode is "common" (default) or "deep" (ports 1–1024, capped).
func (e *Engine) ScanDevicePorts(id, mode string) ([]ports.ServicePort, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "common"
	}
	if mode != "common" && mode != "deep" {
		return nil, fmt.Errorf("invalid mode %q (use common or deep)", mode)
	}
	if !e.tryBeginPortScan(id) {
		return nil, ErrPortScanInProgress
	}
	defer e.endPortScan(id)
	return e.runPortScan(id, mode)
}

func (e *Engine) runPortScan(id, mode string) ([]ports.ServicePort, error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return nil, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return nil, fmt.Errorf("device has no IP")
	}

	var open []ports.ServicePort
	switch mode {
	case "deep":
		open = ports.ScanPortsRange(dev.IP, ports.DefaultDeepStart, ports.DefaultDeepEnd, 128, 80*time.Millisecond)
	default:
		open = ports.ScanPorts(dev.IP)
	}

	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("device not found")
	}
	d.OpenPorts = open
	out := *d
	e.mu.Unlock()

	e.persistDevice(out)
	e.recordEvent("portscan", out.ID, fmt.Sprintf("Port scan (%s): %d open", mode, len(open)))
	e.emitEvent("device_updated", &out)
	e.emitEvent("portscan_complete", map[string]interface{}{
		"id":         out.ID,
		"mode":       mode,
		"open_ports": open,
	})
	return open, nil
}

// ListDeviceHistory returns newest-first presence events for a device.
func (e *Engine) ListDeviceHistory(id string, limit int) ([]Event, error) {
	if _, ok := e.GetDevice(id); !ok {
		return nil, fmt.Errorf("device not found")
	}
	if e.persist == nil {
		return []Event{}, nil
	}
	if limit <= 0 {
		limit = 50
	}
	return e.persist.ListEvents(id, limit)
}

// IsScanning returns true if a scan is currently running.
func (e *Engine) IsScanning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isScanning
}

// PerformScan executes a complete network discovery pass.
func (e *Engine) PerformScan(netInfo *network.Info) ([]Device, error) {
	e.mu.Lock()
	if e.isScanning {
		e.mu.Unlock()
		return e.GetDevices(), nil
	}
	e.isScanning = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.isScanning = false
		e.mu.Unlock()
	}()

	e.emitEvent("scan_start", map[string]string{
		"subnet": netInfo.SubnetCIDR,
		"ssid":   netInfo.SSID,
	})

	rawDevices, err := e.netScanner.PerformScan(netInfo.SubnetCIDR, func(current, total int) {
		e.emitEvent("scan_progress", map[string]int{
			"scanned": current,
			"total":   total,
		})
	})
	if err != nil {
		e.emitEvent("scan_error", err.Error())
		return nil, err
	}

	now := time.Now()
	wasOnline := make(map[string]bool)

	e.mu.Lock()
	for id, dev := range e.devices {
		wasOnline[id] = dev.IsOnline
	}
	e.mu.Unlock()

	seenIDs := make(map[string]bool)
	var seenMu sync.Mutex

	var wg sync.WaitGroup
	deviceChan := make(chan scanner.RawDevice, len(rawDevices))
	for _, raw := range rawDevices {
		deviceChan <- raw
	}
	close(deviceChan)

	concurrency := 8 // keep low so reverse-DNS/mDNS during fingerprinting stays reliable
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range deviceChan {
				isGateway := raw.IP == netInfo.GatewayIP
				isHost := raw.IP == netInfo.IP || (raw.MAC != "" && strings.EqualFold(raw.MAC, netInfo.MAC))
				macVendor := oui.LookupVendor(raw.MAC)

				hostCompName := ""
				if isHost {
					hostCompName = netInfo.ComputerName
				}

				details := e.mdnsResolver.ResolveDevice(raw.IP, raw.MAC, macVendor, isGateway, hostCompName, raw.Hostname)
				id := e.upsertDevice(raw, details, macVendor, now, wasOnline)
				if id != "" {
					seenMu.Lock()
					seenIDs[id] = true
					seenMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Apply offline debounce for devices not seen this scan.
	wentOffline, toPersist := e.applyMisses(seenIDs, wasOnline)

	for _, d := range wentOffline {
		e.recordEvent("offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
		e.emitEvent("device_offline", d)
		e.emitEvent("device_updated", d)
	}
	for _, d := range toPersist {
		e.persistDevice(d)
	}

	finalList := e.GetDevices()
	e.emitEvent("scan_complete", map[string]interface{}{
		"total_devices": len(finalList),
		"timestamp":     now.Format(time.RFC3339),
	})

	return finalList, nil
}

// applyMisses increments miss counters for devices absent from this scan and
// marks them offline only after offlineMissThreshold consecutive misses.
func (e *Engine) applyMisses(seenIDs, wasOnline map[string]bool) (wentOffline, toPersist []Device) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for id, dev := range e.devices {
		if seenIDs[id] {
			e.missCount[id] = 0
			toPersist = append(toPersist, *dev)
			continue
		}
		e.missCount[id]++
		if e.missCount[id] >= offlineMissThreshold && dev.IsOnline {
			dev.IsOnline = false
			wentOffline = append(wentOffline, *dev)
		}
		toPersist = append(toPersist, *dev)
	}
	return wentOffline, toPersist
}

// upsertDevice merges a scanned host into inventory using stable identity rules.
// Returns the stable device ID. Caller must NOT hold e.mu.
func (e *Engine) upsertDevice(raw scanner.RawDevice, details mdns.DeviceDetails, macVendor string, now time.Time, wasOnline map[string]bool) string {
	normMAC := NormalizeMAC(raw.MAC)
	private := IsPrivateMAC(normMAC)

	e.mu.Lock()

	existing, found, previousMAC := e.findDeviceLocked(normMAC, raw.IP, details.Hostname)

	if !found {
		id := DeviceID(normMAC, raw.IP)
		host, src := mdns.PreferHostname("", mdns.NameSourceNone, details.Hostname, details.NameSource)
		newDev := &Device{
			ID:           id,
			IP:           raw.IP,
			MAC:          normMAC,
			Vendor:       macVendor,
			Hostname:     host,
			NameSource:   src,
			DeviceType:   details.DeviceType,
			Icon:         details.Icon,
			Model:        details.Model,
			Services:     details.Services,
			LatencyMs:    raw.LatencyMs,
			IsOnline:     true,
			IsPrivateMAC: private,
			FirstSeen:    now,
			LastSeen:     now,
		}
		e.devices[id] = newDev
		e.missCount[id] = 0
		out := *newDev
		e.mu.Unlock()

		e.persistDevice(out)
		e.recordEvent("found", out.ID, fmt.Sprintf("Discovered %s (%s)", out.DisplayName(), out.IP))
		e.emitEvent("device_found", &out)
		if out.Hostname == "" {
			go e.backgroundNameResolve(out.ID)
		}
		return id
	}

	oldID := existing.ID
	wasPreviouslyOnline := existing.IsOnline
	if wasOnline != nil {
		wasPreviouslyOnline = wasOnline[existing.ID]
	}
	cameOnline := !wasPreviouslyOnline

	existing.IsOnline = true
	existing.LastSeen = now
	existing.LatencyMs = raw.LatencyMs
	existing.IP = raw.IP

	if normMAC != "" {
		if existing.MAC != "" && existing.MAC != normMAC {
			if previousMAC == "" {
				previousMAC = existing.MAC
			}
			existing.PreviousMACs = appendUniqueMAC(existing.PreviousMACs, previousMAC)
		}
		existing.MAC = normMAC
		existing.IsPrivateMAC = private
		existing.Vendor = macVendor

		if strings.HasPrefix(existing.ID, "ip:") {
			newID := DeviceID(normMAC, raw.IP)
			if newID != "" && newID != existing.ID {
				delete(e.devices, existing.ID)
				delete(e.missCount, existing.ID)
				existing.ID = newID
				e.devices[newID] = existing
			}
		}
	}

	if details.Hostname != "" || details.NameSource != "" {
		existing.Hostname, existing.NameSource = mdns.PreferHostname(
			existing.Hostname, existing.NameSource,
			details.Hostname, details.NameSource,
		)
	}
	// Model/type are fingerprint hints only — never written into Hostname.
	if details.DeviceType != "" {
		existing.DeviceType = details.DeviceType
		existing.Icon = details.Icon
		existing.Model = details.Model
	}
	existing.Services = details.Services
	e.missCount[existing.ID] = 0
	if oldID != existing.ID {
		if wasOnline != nil {
			if v, ok := wasOnline[oldID]; ok {
				wasOnline[existing.ID] = v
			}
		}
	}

	out := *existing
	e.mu.Unlock()

	e.persistDevice(out)
	if cameOnline {
		e.recordEvent("online", out.ID, fmt.Sprintf("%s is online", out.DisplayName()))
		if out.Hostname == "" {
			go e.backgroundNameResolve(out.ID)
		}
	}
	e.emitEvent("device_updated", &out)
	return out.ID
}

// findDeviceLocked resolves an existing device by MAC, IP fallback, or private-MAC hostname merge.
// Must be called with e.mu held.
func (e *Engine) findDeviceLocked(normMAC, ip, hostname string) (dev *Device, found bool, previousMAC string) {
	if normMAC != "" {
		if d, ok := e.devices[DeviceID(normMAC, "")]; ok {
			return d, true, ""
		}
		for _, d := range e.devices {
			if d.MAC != "" && d.MAC == normMAC {
				return d, true, ""
			}
			for _, prev := range d.PreviousMACs {
				if prev == normMAC {
					return d, true, ""
				}
			}
		}
	}

	if ip != "" {
		if d, ok := e.devices[DeviceID("", ip)]; ok {
			return d, true, ""
		}
		for _, d := range e.devices {
			if d.IP == ip {
				return d, true, ""
			}
		}
	}

	if normMAC != "" && IsPrivateMAC(normMAC) && hostname != "" {
		want := strings.ToLower(strings.TrimSpace(hostname))
		for _, d := range e.devices {
			if d.Hostname == "" {
				continue
			}
			if strings.ToLower(strings.TrimSpace(d.Hostname)) == want {
				return d, true, d.MAC
			}
		}
	}

	return nil, false, ""
}

func appendUniqueMAC(list []string, mac string) []string {
	if mac == "" {
		return list
	}
	for _, m := range list {
		if m == mac {
			return list
		}
	}
	return append(list, mac)
}

func compareIPs(ip1, ip2 string) bool {
	p1 := strings.Split(ip1, ".")
	p2 := strings.Split(ip2, ".")
	if len(p1) != 4 || len(p2) != 4 {
		return ip1 < ip2
	}
	for i := 0; i < 4; i++ {
		var n1, n2 int
		_, _ = parseDec(p1[i], &n1)
		_, _ = parseDec(p2[i], &n2)
		if n1 != n2 {
			return n1 < n2
		}
	}
	return false
}

func parseDec(s string, out *int) (bool, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false, nil
		}
		n = n*10 + int(ch-'0')
	}
	*out = n
	return true, nil
}
