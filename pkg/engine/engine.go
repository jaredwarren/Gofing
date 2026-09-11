package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/notify"
	"github.com/jaredwarren/Gofing/pkg/ports"
	"github.com/jaredwarren/Gofing/pkg/probes"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// Device represents an enriched network device.
type Device struct {
	ID                 string              `json:"id"`
	NetworkKey         string              `json:"network_key,omitempty"` // SSID / gateway scope
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

	// Tier-3 enrichment bookkeeping. A zero LastEnrichedAt means "never
	// fingerprinted" and always qualifies for enrichment.
	LastEnrichedAt time.Time `json:"last_enriched_at"`
	EnrichFailures int       `json:"enrich_failures,omitempty"`
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
	// mu guards the device map and everything derived from it. Never hold it
	// across I/O; never emit or persist while holding it.
	mu        sync.RWMutex
	devices   map[string]*Device // keyed by stable Device.ID
	missCount map[string]int     // consecutive scan misses per device ID
	// verifyMiss counts consecutive failures of the patient verification probe.
	// Kept apart from missCount because ARP hits reset that one on every
	// intervening pass, which would otherwise make verification unable to ever
	// retire a device whose kernel ARP entry outlives its departure.
	verifyMiss map[string]int

	// settingsMu guards settings alone. Every tier timer reads it on each tick
	// and fireAlert reads it on every transition, none of which concerns the
	// device map — so it must not contend with the device writers.
	settingsMu sync.RWMutex
	settings   Settings

	// listenersMu guards listeners alone. emitEvent reads it for every SSE frame.
	listenersMu sync.RWMutex
	listeners   []EventFunc

	// alertMu guards the per-device alert damping timestamps. Separate from
	// e.mu because fireAlert runs on every presence transition and has nothing
	// to do with the device map.
	alertMu     sync.Mutex
	lastAlertAt map[string]time.Time

	portScanMu       sync.Mutex
	portScanInflight map[string]bool
	netScanner       *scanner.Scanner
	mdnsResolver     *mdns.Resolver
	persist          Persistence
	warmHostFn       func(ctx context.Context, ip string)
	deepLookupFn     func(ctx context.Context, r *mdns.Resolver, ip string) mdns.LookupResult
	activeNetworkKey string
	activeSubnetCIDR string
	netInfo          *network.Info // cached active network; refreshed by currentNetInfo
	netInfoAt        time.Time
	netDetectFn      func() (*network.Info, error) // tests override OS network detection
	discCtx          context.Context
	probeFn          func(ctx context.Context, ip string) (latency float64, ok bool)
	arpFn            func(ctx context.Context) ([]scanner.RawDevice, error)
	verifyFn         func(ctx context.Context, ip string) (latency float64, ok bool)
	presencePass     atomic.Uint64 // presence tick counter; paces verification passes
	sweepFn          func(ctx context.Context, subnetCIDR, iface string, skipHits map[string]float64, progress func(int, int)) ([]scanner.RawDevice, error)
	notifyFn         func(title, message string) error
	startupPresence  bool // true until the first presence pass; suppresses launch online alerts

	// Per-tier single-flight gates. Different tiers overlap freely.
	presenceGate  tierGate
	discoveryGate tierGate
	tiersOnce     sync.Once
	lastPresence  PresenceResult // newest Tier-1 snapshot; feeds the sweep's skip list

	// Tier 3: queue-driven fingerprinting.
	enrichQ     *enrichQueue
	resolveFn   func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails
	vendorFn    func(mac string) string
	deepProbeFn func(ctx context.Context, ip string, knownPorts []int) probes.ProbeResult
}

// New returns an initialized Engine. persist may be nil (in-memory only).
func New(persist Persistence) *Engine {
	e := &Engine{
		devices:          make(map[string]*Device),
		missCount:        make(map[string]int),
		lastAlertAt:      make(map[string]time.Time),
		verifyMiss:       make(map[string]int),
		portScanInflight: make(map[string]bool),
		enrichQ:          newEnrichQueue(),
		netScanner:       scanner.New(),
		mdnsResolver:     mdns.New(),
		persist:          persist,
		warmHostFn:       warmHost,
		deepLookupFn: func(ctx context.Context, r *mdns.Resolver, ip string) mdns.LookupResult {
			return r.LookupHostnameDeepCtx(ctx, ip)
		},
		startupPresence: true,
	}
	e.settings = DefaultSettings()
	e.loadFromStore()
	e.loadSettings()
	return e
}

// Start begins process-lifetime discovery helpers (always-on mDNS).
func (e *Engine) Start(ctx context.Context, info *network.Info) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Lock()
	e.discCtx = ctx
	if e.notifyFn == nil {
		e.notifyFn = notify.Show
	}
	e.mu.Unlock()

	if e.mdnsResolver != nil {
		e.mdnsResolver.SetNameLearnedHandler(e.onNameLearned)
	}
	if info != nil {
		e.SetActiveNetwork(info)
		e.listenMDNS(info.InterfaceName)
	}
	e.StartTiers(ctx)
}

// SetNotifyFn overrides the notification delivery function.
func (e *Engine) SetNotifyFn(fn func(title, message string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notifyFn = fn
}

func (e *Engine) listenMDNS(iface string) {
	e.mu.RLock()
	ctx := e.discCtx
	r := e.mdnsResolver
	e.mu.RUnlock()
	if r == nil || ctx == nil || iface == "" {
		return
	}
	r.Listen(ctx, iface)
}

// onNameLearned applies a multicast hostname to any device currently at that IP.
func (e *Engine) onNameLearned(ip, hostname, source string) {
	if ip == "" || hostname == "" {
		return
	}
	e.mu.Lock()
	var changed []Device
	for _, d := range e.devices {
		if d.IP != ip {
			continue
		}
		before := d.Hostname
		beforeSrc := d.NameSource
		d.Hostname, d.NameSource = mdns.PreferHostname(d.Hostname, d.NameSource, hostname, source)
		if d.Hostname != before || d.NameSource != beforeSrc {
			changed = append(changed, *d)
		}
	}
	e.mu.Unlock()

	for i := range changed {
		d := changed[i]
		e.persistDevice(d)
		e.emitEvent("device_updated", &d)
	}
}

func (e *Engine) loadFromStore() {
	if e.persist == nil {
		return
	}
	loaded, err := e.persist.LoadDevices()
	if err != nil || len(loaded) == 0 {
		return
	}
	var pruned []string

	e.mu.Lock()
	for i := range loaded {
		d := loaded[i]
		d.IsOnline = false
		if d.ID == "" {
			d.ID = DeviceID(d.MAC, d.IP)
		}
		if isPhantomRow(d) {
			pruned = append(pruned, d.ID)
			continue
		}
		d.Hostname, d.NameSource = mdns.PreferHostname("", mdns.NameSourceNone, d.Hostname, d.NameSource)
		if d.Hostname == "" {
			d.NameSource = mdns.NameSourceNone
		}
		// Rows persisted before enrichment existed have no LastEnrichedAt. Treat
		// an already-identified device's last sighting as its last fingerprint so
		// the TTL staggers them instead of flushing the whole inventory into the
		// queue on the first start after an upgrade.
		if d.LastEnrichedAt.IsZero() && d.Hostname != "" && d.DeviceType != "" {
			d.LastEnrichedAt = d.LastSeen
		}
		cp := d
		e.devices[cp.ID] = &cp
	}
	for _, dev := range e.devices {
		if dev.Hostname == "" || isGenericHostname(dev.Hostname) {
			e.adoptDeviceMetadataLocked(dev)
			if dev.Hostname == "" {
				if bestName, bestSrc := e.findBestNameLocked(dev); bestName != "" {
					dev.Hostname = bestName
					dev.NameSource = bestSrc
				}
			}
		}
	}
	e.mu.Unlock()

	// Deleting is I/O, so it happens after the lock is released.
	for _, id := range pruned {
		e.deletePersisted(id)
	}
	if len(pruned) > 0 {
		slog.Info("pruned phantom device rows with no Layer-2 identity",
			"pruned", len(pruned), "kept", len(loaded)-len(pruned))
	}
}

// isPhantomRow reports whether a persisted device is an artifact of the probe
// false positives the sweep used to accept: an address that answered a
// concurrent probe but never had an ARP entry, recorded with no MAC and never
// given a name, vendor or type.
//
// Such a row can never be matched again — identity needs a MAC, and the
// address gets reused — so it can only sit offline or flap. It is dropped on
// load, but only when it carries nothing a person put there: a custom name,
// note, type override, learned hostname, prior MAC or port-scan result all
// mean keep it and let the user decide.
func isPhantomRow(d Device) bool {
	if d.MAC != "" {
		return false
	}
	return d.Hostname == "" &&
		d.CustomName == "" &&
		d.Note == "" &&
		d.DeviceTypeOverride == "" &&
		len(d.PreviousMACs) == 0 &&
		len(d.OpenPorts) == 0
}

// RegisterEventListener adds a subscriber for scan events.
func (e *Engine) RegisterEventListener(fn EventFunc) {
	e.listenersMu.Lock()
	defer e.listenersMu.Unlock()
	e.listeners = append(e.listeners, fn)
}

func (e *Engine) emitEvent(eventType string, data interface{}) {
	e.listenersMu.RLock()
	listeners := make([]EventFunc, len(e.listeners))
	copy(listeners, e.listeners)
	e.listenersMu.RUnlock()

	for _, l := range listeners {
		l(eventType, data)
	}
}

func (e *Engine) persistDevice(d Device) {
	if e.persist == nil {
		return
	}
	if err := e.persist.SaveDevice(d); err != nil {
		slog.Error("Failed to save device", "id", d.ID, "error", err)
	}
}

func (e *Engine) deletePersisted(id string) {
	if e.persist == nil || id == "" {
		return
	}
	if err := e.persist.DeleteDevice(id); err != nil {
		slog.Error("Failed to delete device", "id", id, "error", err)
	}
}

func (e *Engine) persistDevices(devices []Device) {
	if e.persist == nil || len(devices) == 0 {
		return
	}
	if err := e.persist.SaveDevices(devices); err != nil {
		slog.Error("Failed to batch save devices", "count", len(devices), "error", err)
	}
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

// SetActiveNetwork updates which LAN inventory is visible. Call when Wi‑Fi/network changes.
func (e *Engine) SetActiveNetwork(info *network.Info) {
	e.mu.Lock()
	e.setActiveNetworkLocked(info)
	migrated, deleted := e.reconcileScopedIDsLocked()
	e.mu.Unlock()
	for _, id := range deleted {
		e.deletePersisted(id)
	}
	e.persistDevices(migrated)
}

func (e *Engine) setActiveNetworkLocked(info *network.Info) {
	prev := e.activeNetworkKey
	e.activeNetworkKey = NetworkKeyFromInfo(info)
	e.activeSubnetCIDR = ""
	if info != nil {
		e.activeSubnetCIDR = info.SubnetCIDR
		e.netInfo = info
		e.netInfoAt = time.Now()
	}
	if prev != "" && e.activeNetworkKey != "" && prev != e.activeNetworkKey {
		// Drop miss counters for the previous LAN; they are not offline on this network.
		for id, dev := range e.devices {
			if networkKeysEquivalent(dev.NetworkKey, prev) {
				e.missCount[id] = 0
			}
		}
	}
}

// reconcileScopedIDsLocked remounts devices onto the sanitized active network key.
// Repairs: wired SSID placeholders, legacy CIDR-slash gw/subnet keys, and IDs
// corrupted by first-slash stripNetworkScope. Caller holds e.mu.
func (e *Engine) reconcileScopedIDsLocked() (migrated []Device, deleted []string) {
	netKey := e.activeNetworkKey
	if netKey == "" {
		return nil, nil
	}

	type pending struct {
		oldID string
		dev   *Device
	}
	var work []pending
	for id, d := range e.devices {
		if !e.deviceNeedsReconcileLocked(d) {
			continue
		}
		desiredID := ScopedDeviceID(netKey, d.MAC, d.IP)
		if desiredID == "" {
			continue
		}
		if id == desiredID && d.NetworkKey == netKey {
			continue
		}
		work = append(work, pending{oldID: id, dev: d})
	}

	for _, w := range work {
		d := w.dev
		oldID := w.oldID
		desiredID := ScopedDeviceID(netKey, d.MAC, d.IP)
		if desiredID == "" {
			continue
		}
		if oldID != desiredID {
			delete(e.devices, oldID)
			if mc, ok := e.missCount[oldID]; ok {
				delete(e.missCount, oldID)
				e.missCount[desiredID] = mc
			}
			// Prefer keeping an already-correct row if both old and new exist.
			if existing, ok := e.devices[desiredID]; ok && existing != d {
				mergeDevicePreferRicher(existing, d)
				d = existing
			} else {
				d.ID = desiredID
				e.devices[desiredID] = d
			}
			deleted = append(deleted, oldID)
			e.enrichQ.rekey(oldID, desiredID)
		}
		d.NetworkKey = netKey
		d.ID = desiredID
		if d.Hostname == "" || isGenericHostname(d.Hostname) {
			e.adoptDeviceMetadataLocked(d)
			if d.Hostname == "" {
				if bestName, bestSrc := e.findBestNameLocked(d); bestName != "" {
					d.Hostname = bestName
					d.NameSource = bestSrc
				}
			}
		}
		e.devices[desiredID] = d
		migrated = append(migrated, *d)
	}
	return migrated, deleted
}

func mergeDevicePreferRicher(dst, src *Device) {
	if dst == nil || src == nil || dst == src {
		return
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
		dst.IP = src.IP
		dst.LatencyMs = src.LatencyMs
	}
	if dst.MAC == "" {
		dst.MAC = src.MAC
	}
	if dst.CustomName == "" && src.CustomName != "" {
		dst.CustomName = src.CustomName
	}
	if dst.Hostname == "" || isGenericHostname(dst.Hostname) {
		if src.Hostname != "" && !isGenericHostname(src.Hostname) {
			dst.Hostname = src.Hostname
			dst.NameSource = src.NameSource
		}
	}
	if (dst.Vendor == "" || isGenericLabel(dst.Vendor)) && src.Vendor != "" && !isGenericLabel(src.Vendor) {
		dst.Vendor = src.Vendor
	}
	if (dst.DeviceType == "" || isGenericLabel(dst.DeviceType)) && src.DeviceType != "" {
		dst.DeviceType = src.DeviceType
		dst.Icon = src.Icon
		dst.Model = src.Model
	}
	if src.IsOnline {
		dst.IsOnline = true
	}
	for _, m := range src.PreviousMACs {
		dst.PreviousMACs = appendUniqueMAC(dst.PreviousMACs, m)
	}
}

// networkKeysEquivalent treats sanitized and legacy slash-containing gw/subnet keys as the same LAN.
func networkKeysEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	return normalizeStoredNetworkKey(a) == normalizeStoredNetworkKey(b)
}

// GetDevices returns devices for the active network only, sorted by IP.
func (e *Engine) GetDevices() []Device {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var list []Device
	for _, dev := range e.devices {
		if e.deviceVisibleLocked(dev) {
			list = append(list, *dev)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return compareIPs(list[i].IP, list[j].IP)
	})

	return list
}

// deviceVisibleLocked reports whether a device belongs in the current network view.
func (e *Engine) deviceVisibleLocked(dev *Device) bool {
	if e.activeNetworkKey == "" {
		return true
	}
	if networkKeysEquivalent(dev.NetworkKey, e.activeNetworkKey) {
		return true
	}
	// Old wired placeholder SSID key — show if still on this subnet.
	if isWiredPlaceholderKey(dev.NetworkKey) && ipInCIDR(dev.IP, e.activeSubnetCIDR) {
		return true
	}
	// Legacy rows (pre-network-key): show only if IP is on the active subnet.
	if dev.NetworkKey == "" && ipInCIDR(dev.IP, e.activeSubnetCIDR) {
		return true
	}
	return false
}

// deviceNeedsReconcileLocked is true when a visible/legacy row should be remounted
// onto the sanitized active network key. Caller holds e.mu.
func (e *Engine) deviceNeedsReconcileLocked(dev *Device) bool {
	if e.deviceVisibleLocked(dev) {
		return true
	}
	// Corrupted IDs may have a mismatched NetworkKey vs map key; still migrate if
	// the device IP is on the active subnet and the stored key is gw/subnet-shaped
	// or from a wired placeholder.
	if e.activeSubnetCIDR != "" && ipInCIDR(dev.IP, e.activeSubnetCIDR) {
		nk := normalizeStoredNetworkKey(dev.NetworkKey)
		if strings.HasPrefix(nk, "gw:") || strings.HasPrefix(nk, "subnet:") || isWiredPlaceholderKey(dev.NetworkKey) {
			return true
		}
	}
	return false
}

func (e *Engine) belongsToActiveNetworkLocked(dev *Device) bool {
	return e.deviceVisibleLocked(dev)
}

// GetDevice returns a device by stable ID.
func (e *Engine) GetDevice(id string) (Device, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	d, ok := e.devices[id]
	if !ok {
		base := stripNetworkScope(id)
		if e.activeNetworkKey != "" {
			d, ok = e.devices[e.activeNetworkKey+"/"+base]
		}
		if !ok {
			for _, dev := range e.devices {
				if stripNetworkScope(dev.ID) == base {
					d, ok = dev, true
					break
				}
			}
		}
	}
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
	Device     Device               `json:"device"`
	Found      bool                 `json:"found"`
	Changed    bool                 `json:"changed"`
	Hostname   string               `json:"hostname,omitempty"`
	NameSource string               `json:"name_source,omitempty"`
	Candidates []mdns.NameCandidate `json:"candidates,omitempty"`
	Message    string               `json:"message,omitempty"`
}

// ResolveDeviceName force-fetches Bonjour/DNS names for a device and persists
// an upgrade via ranked PreferHostname. ctx bounds the network probes.
func (e *Engine) ResolveDeviceName(ctx context.Context, id string) (NameResolveResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dev, ok := e.GetDevice(id)
	if !ok {
		return NameResolveResult{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return NameResolveResult{Device: dev, Message: "device has no IP"}, nil
	}

	// Nudge the host so macOS may refresh ARP / mDNS cache entries.
	if e.warmHostFn != nil {
		e.warmHostFn(ctx, dev.IP)
	}

	var candidates []mdns.NameCandidate
	bestName, bestSrc := "", mdns.NameSourceNone

	consider := func(name, source string) {
		name, source = mdns.PreferHostname("", mdns.NameSourceNone, name, source)
		if name == "" {
			return
		}
		candidates = append(candidates, mdns.NameCandidate{Hostname: name, Source: source})
		bestName, bestSrc = mdns.PreferHostname(bestName, bestSrc, name, source)
	}

	if arpName := e.netScanner.ARPHostname(dev.IP); arpName != "" {
		consider(arpName, mdns.NameSourceARP)
	}

	var deep mdns.LookupResult
	if e.deepLookupFn != nil {
		deep = e.deepLookupFn(ctx, e.mdnsResolver, dev.IP)
	}
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
func (e *Engine) LookupDeviceNames(ctx context.Context, id string) (mdns.LookupResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dev, ok := e.GetDevice(id)
	if !ok {
		return mdns.LookupResult{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return mdns.LookupResult{}, nil
	}
	if e.warmHostFn != nil {
		e.warmHostFn(ctx, dev.IP)
	}
	var res mdns.LookupResult
	if e.deepLookupFn != nil {
		res = e.deepLookupFn(ctx, e.mdnsResolver, dev.IP)
	}
	if arpName := e.netScanner.ARPHostname(dev.IP); arpName != "" {
		if h := mdns.SanitizeHostname(arpName); h != "" {
			res.Candidates = append([]mdns.NameCandidate{{Hostname: h, Source: mdns.NameSourceARP}}, res.Candidates...)
			res.Hostname, res.NameSource = mdns.PreferHostname(res.Hostname, res.NameSource, h, mdns.NameSourceARP)
		}
	}
	return res, nil
}

// UpsertForTest seeds a device through the normal identity rules. Exported so
// tests in other packages can build a realistic inventory.
func (e *Engine) UpsertForTest(raw scanner.RawDevice, details mdns.DeviceDetails,
	vendor string, now time.Time) string {
	return e.upsertDevice(raw, details, vendor, now, nil)
}

// SetEnrichTestHooks overrides the Tier-3 network probes so enrichment can be
// exercised without touching the network. Either may be nil to keep the real one.
func (e *Engine) SetEnrichTestHooks(
	resolve func(ctx context.Context, in mdns.ResolveInput) mdns.DeviceDetails,
	vendor func(mac string) string,
) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resolveFn = resolve
	e.vendorFn = vendor
}

// SetProbeTestHook overrides deep device fingerprinting probes for unit testing.
func (e *Engine) SetProbeTestHook(probe func(ctx context.Context, ip string, knownPorts []int) probes.ProbeResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deepProbeFn = probe
}

func (e *Engine) probeDevice(ctx context.Context, ip string, knownPorts []int) probes.ProbeResult {
	e.mu.RLock()
	fn := e.deepProbeFn
	isTestResolve := e.resolveFn != nil
	e.mu.RUnlock()
	if fn != nil {
		return fn(ctx, ip, knownPorts)
	}
	if isTestResolve {
		return probes.ProbeResult{IP: ip}
	}
	return probes.ProbeDevice(ctx, ip, knownPorts)
}

// SetTestHooks configures custom network lookup functions for unit testing.
func (e *Engine) SetTestHooks(warmHost func(ctx context.Context, ip string), deepLookup func(ctx context.Context, r *mdns.Resolver, ip string) mdns.LookupResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.warmHostFn = warmHost
	e.deepLookupFn = deepLookup
}

func warmHost(ctx context.Context, ip string) {
	if ctx == nil {
		ctx = context.Background()
	}
	pingCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(pingCtx, "ping", "-c", "1", "-W", "500", ip)
	_ = cmd.Run()
}

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

const (
	portScanCommonBudget = 30 * time.Second
	portScanDeepBudget   = 60 * time.Second
)

// TryStartPortScan validates and launches an async port scan. started=false means
// one is already in flight for this device (not an error).
//
// The caller's context is intentionally unused: the scan runs on a detached
// timeout so an HTTP handler returning after scan_started cannot cancel it.
func (e *Engine) TryStartPortScan(_ context.Context, id, mode string) (started bool, err error) {
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
	budget := portScanCommonBudget
	if mode == "deep" {
		budget = portScanDeepBudget
	}
	scanCtx, cancel := context.WithTimeout(context.Background(), budget)
	go func() {
		defer cancel()
		defer e.endPortScan(id)
		if _, err := e.runPortScan(scanCtx, id, mode); err != nil {
			slog.Error("port scan failed", "id", id, "mode", mode, "error", err)
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
func (e *Engine) ScanDevicePorts(ctx context.Context, id, mode string) ([]ports.ServicePort, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	return e.runPortScan(ctx, id, mode)
}

func (e *Engine) runPortScan(ctx context.Context, id, mode string) ([]ports.ServicePort, error) {
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
		open = ports.ScanPortsRange(ctx, dev.IP, ports.DefaultDeepStart, ports.DefaultDeepEnd, 128, 80*time.Millisecond)
	default:
		open = ports.ScanPorts(ctx, dev.IP)
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

// IsScanning reports whether a discovery sweep is in flight. Presence and
// enrichment run continuously and are reported separately via TierStatus.
func (e *Engine) IsScanning() bool {
	return e.discoveryGate.running()
}

// upsertOpts controls the side effects of a single upsert. Making these
// explicit replaces an unsynchronized read of isScanning that used to decide,
// invisibly, whether a caller was responsible for persisting.
type upsertOpts struct {
	Persist    bool // false when the caller batch-persists the whole pass afterwards
	EmitFound  bool
	EmitUpdate bool

	// RequireMACForNew refuses to *create* a device from a row with no MAC.
	// Such a row may still update a device already known at that IP.
	//
	// Without this, any probe false positive becomes a permanent inventory
	// entry: MAC-less, nameless, vendorless, and never matchable again once the
	// address is reused, so it can only ever sit offline or flap. A device on a
	// directly-connected subnet always has a MAC; if we could not learn one,
	// we have not identified a device.
	RequireMACForNew bool
}

// upsertDevice merges a scanned host into inventory using stable identity rules,
// persisting and emitting immediately. Returns the stable device ID.
// Caller must NOT hold e.mu.
func (e *Engine) upsertDevice(raw scanner.RawDevice, details mdns.DeviceDetails, macVendor string, now time.Time, wasOnline map[string]bool) string {
	return e.upsertDeviceOpts(raw, details, macVendor, now, wasOnline,
		upsertOpts{Persist: true, EmitFound: true, EmitUpdate: true})
}

// upsertDeviceOpts is upsertDevice with explicit control over persistence and
// event emission. Caller must NOT hold e.mu.
func (e *Engine) upsertDeviceOpts(raw scanner.RawDevice, details mdns.DeviceDetails, macVendor string, now time.Time, wasOnline map[string]bool, opts upsertOpts) string {
	normMAC := NormalizeMAC(raw.MAC)
	private := IsPrivateMAC(normMAC)

	e.mu.Lock()
	netKey := e.activeNetworkKey

	existing, found, previousMAC := e.findDeviceLocked(normMAC, raw.IP, details.Hostname)

	if !found {
		if normMAC == "" && opts.RequireMACForNew {
			e.mu.Unlock()
			slog.Debug("discarded device with no Layer-2 identity", "ip", raw.IP)
			return ""
		}
		desiredID := ScopedDeviceID(netKey, normMAC, raw.IP)
		host, src := mdns.PreferHostname("", mdns.NameSourceNone, details.Hostname, details.NameSource)
		newDev := &Device{
			ID:           desiredID,
			NetworkKey:   netKey,
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
			IsPrivateMAC: private,
			FirstSeen:    now,
			LastSeen:     now,
		}
		if newDev.Hostname == "" || isGenericHostname(newDev.Hostname) {
			e.adoptDeviceMetadataLocked(newDev)
			if newDev.Hostname == "" {
				if bestName, bestSrc := e.findBestNameLocked(newDev); bestName != "" {
					newDev.Hostname = bestName
					newDev.NameSource = bestSrc
				}
			}
		}
		e.setOnlineLocked(newDev, true)
		e.devices[desiredID] = newDev
		e.missCount[desiredID] = 0
		out := *newDev
		e.mu.Unlock()

		if opts.Persist {
			e.persistDevice(out)
		}
		e.recordEvent("found", out.ID, fmt.Sprintf("Discovered %s (%s)", out.DisplayName(), out.IP))
		if opts.EmitFound {
			e.emitEvent("device_found", &out)
		}
		e.fireAlert(AlertRuleNewDevice, out.ID, fmt.Sprintf("New device: %s (%s)", out.DisplayName(), out.IP))
		return desiredID
	}

	oldID := existing.ID
	beforeUpsert := *existing
	wasPreviouslyOnline := existing.IsOnline
	if wasOnline != nil {
		wasPreviouslyOnline = wasOnline[existing.ID]
	}
	cameOnline := !wasPreviouslyOnline

	e.setOnlineLocked(existing, true)
	existing.LastSeen = now
	existing.LatencyMs = raw.LatencyMs
	existing.IP = raw.IP
	existing.NetworkKey = netKey

	if normMAC != "" {
		if existing.MAC != "" && existing.MAC != normMAC {
			if previousMAC == "" {
				previousMAC = existing.MAC
			}
			existing.PreviousMACs = appendUniqueMAC(existing.PreviousMACs, previousMAC)
		}
		existing.MAC = normMAC
		existing.IsPrivateMAC = private
		if existing.Vendor == "" || isGenericLabel(existing.Vendor) || !isGenericLabel(macVendor) {
			existing.Vendor = macVendor
		}
	}

	// Remount ID when adding network scope or upgrading ip:→MAC; keep base ID
	// stable across private-MAC rotation.
	base := stripNetworkScope(existing.ID)
	if strings.HasPrefix(base, "ip:") && normMAC != "" {
		base = DeviceID(normMAC, "")
	}
	desiredID := base
	if netKey != "" {
		desiredID = netKey + "/" + base
	}
	if desiredID != "" && desiredID != existing.ID {
		delete(e.devices, existing.ID)
		delete(e.missCount, existing.ID)
		existing.ID = desiredID
		e.devices[desiredID] = existing
	}

	applyDetailsLocked(existing, details, "")
	if existing.Hostname == "" || isGenericHostname(existing.Hostname) {
		e.adoptDeviceMetadataLocked(existing)
		if existing.Hostname == "" {
			if bestName, bestSrc := e.findBestNameLocked(existing); bestName != "" {
				existing.Hostname = bestName
				existing.NameSource = bestSrc
			}
		}
	}
	e.missCount[existing.ID] = 0
	if oldID != existing.ID {
		if wasOnline != nil {
			if v, ok := wasOnline[oldID]; ok {
				wasOnline[existing.ID] = v
			}
		}
	}

	out := *existing
	migratedFrom := ""
	if oldID != existing.ID {
		migratedFrom = oldID
	}
	e.mu.Unlock()

	if migratedFrom != "" {
		e.deletePersisted(migratedFrom)
		e.enrichQ.rekey(migratedFrom, out.ID)
	}
	if opts.Persist {
		e.persistDevice(out)
	}
	if cameOnline {
		e.recordEvent("online", out.ID, fmt.Sprintf("%s is online", out.DisplayName()))
		e.fireAlert(AlertRuleDeviceOnline, out.ID, fmt.Sprintf("%s came back online", out.DisplayName()))
	}
	if opts.EmitUpdate && (cameOnline || migratedFrom != "" ||
		deviceChangedMeaningfully(beforeUpsert, out)) {
		e.emitEvent("device_updated", &out)
	}
	return out.ID
}

// setOnlineLocked is the single writer for Device.IsOnline (besides startup
// load which forces false). Any tier may prove a device present; only Tier 1
// declares absence. Caller must hold e.mu.
func (e *Engine) setOnlineLocked(d *Device, online bool) {
	if d == nil {
		return
	}
	d.IsOnline = online
}

// applyDetailsLocked merges resolved fingerprint details into d using the ranked
// name rules. Caller must hold e.mu, and must emit and persist only after
// unlocking. An empty vendor leaves d.Vendor alone. Returns true if any
// user-visible field changed.
//
// Both the discovery sweep and the enrichment tier merge through here, so the
// precedence rules exist in exactly one place.
func applyDetailsLocked(d *Device, details mdns.DeviceDetails, vendor string) bool {
	before := *d

	if details.Hostname != "" || details.NameSource != "" {
		d.Hostname, d.NameSource = mdns.PreferHostname(
			d.Hostname, d.NameSource,
			details.Hostname, details.NameSource,
		)
	}
	// Model/type are fingerprint hints only — never written into Hostname.
	if details.DeviceType != "" {
		d.DeviceType = details.DeviceType
		d.Icon = details.Icon
		d.Model = details.Model
	}
	// A probe that timed out returns no services; that is not evidence the
	// device stopped offering the ones we already know about.
	if len(details.Services) > 0 {
		d.Services = details.Services
	}
	// Likewise, a local-only vendor miss must not erase a known vendor.
	if vendor != "" {
		d.Vendor = vendor
	}

	return before.Hostname != d.Hostname ||
		before.NameSource != d.NameSource ||
		before.DeviceType != d.DeviceType ||
		before.Icon != d.Icon ||
		before.Model != d.Model ||
		before.Vendor != d.Vendor ||
		!sameStrings(before.Services, d.Services)
}

// sameStrings reports whether two string slices hold the same values in order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// applyProbeResultLocked integrates findings from deep protocol probes into d.
// Returns true if any user-visible field changed. Caller must hold e.mu.
func applyProbeResultLocked(d *Device, res probes.ProbeResult) bool {
	before := *d

	// 1. UPnP / SSDP
	if res.UPnP != nil {
		if res.UPnP.ModelName != "" && (d.Model == "" || isGenericHostname(d.Model)) {
			d.Model = res.UPnP.ModelName
			if res.UPnP.ModelNumber != "" && !strings.Contains(d.Model, res.UPnP.ModelNumber) {
				d.Model = fmt.Sprintf("%s (%s)", d.Model, res.UPnP.ModelNumber)
			}
		}
		if res.UPnP.Manufacturer != "" && (!vendorKnown(d.Vendor) || strings.EqualFold(d.Vendor, "generic") || strings.EqualFold(d.Vendor, "unknown")) {
			d.Vendor = res.UPnP.Manufacturer
		}
		if res.UPnP.FriendlyName != "" {
			d.Hostname, d.NameSource = mdns.PreferHostname(
				d.Hostname, d.NameSource,
				res.UPnP.FriendlyName, mdns.NameSourceUPnP,
			)
		}
		d.Services = addServiceTag(d.Services, "UPnP")
	}

	// 2. NetBIOS
	if res.NetBIOS != nil {
		if res.NetBIOS.ComputerName != "" {
			d.Hostname, d.NameSource = mdns.PreferHostname(
				d.Hostname, d.NameSource,
				res.NetBIOS.ComputerName, mdns.NameSourceNetBIOS,
			)
		}
		d.Services = addServiceTag(d.Services, "NetBIOS")
		if res.NetBIOS.Workgroup != "" {
			d.Services = addServiceTag(d.Services, "Workgroup: "+res.NetBIOS.Workgroup)
		}
	}

	// 3. Roku ECP — the owner-assigned name ("Living room 2"), plus an exact
	// model. Checked before TLS because it is a far stronger identity signal.
	if res.Roku != nil {
		if res.Roku.Name != "" {
			d.Hostname, d.NameSource = mdns.PreferHostname(
				d.Hostname, d.NameSource,
				res.Roku.Name, mdns.NameSourceECP,
			)
		}
		if res.Roku.ModelName != "" && (d.Model == "" || isGenericHostname(d.Model)) {
			d.Model = res.Roku.ModelName
			if res.Roku.ModelNumber != "" && !strings.Contains(d.Model, res.Roku.ModelNumber) {
				d.Model = fmt.Sprintf("%s (%s)", d.Model, res.Roku.ModelNumber)
			}
		}
		if res.Roku.VendorName != "" && !vendorKnown(d.Vendor) {
			d.Vendor = res.Roku.VendorName
		}
		if d.DeviceType == "" || d.DeviceType == "Generic Device" {
			d.DeviceType = "Media Player"
			d.Icon = "tv"
		}
		d.Services = addServiceTag(d.Services, "Roku ECP")
	}

	// 4. TLS Certificate
	if res.TLS != nil {
		if res.TLS.SubjectCN != "" {
			d.Hostname, d.NameSource = mdns.PreferHostname(
				d.Hostname, d.NameSource,
				res.TLS.SubjectCN, mdns.NameSourceTLS,
			)
		}
		d.Services = addServiceTag(d.Services, "TLS Cert")
	}

	return before.Hostname != d.Hostname ||
		before.NameSource != d.NameSource ||
		before.Model != d.Model ||
		before.Vendor != d.Vendor ||
		!sameStrings(before.Services, d.Services)
}

func addServiceTag(services []string, tag string) []string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return services
	}
	for _, s := range services {
		if strings.EqualFold(s, tag) {
			return services
		}
	}
	return append(services, tag)
}

// ProbeDevice executes multi-protocol fingerprinting against a device on demand,
// merges findings, persists, emits device_updated, and returns the probe results.
func (e *Engine) ProbeDevice(ctx context.Context, id string) (probes.ProbeResult, Device, error) {
	dev, ok := e.GetDevice(id)
	if !ok {
		return probes.ProbeResult{}, Device{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return probes.ProbeResult{}, dev, fmt.Errorf("device has no IP address")
	}

	var openPorts []int
	for _, sp := range dev.OpenPorts {
		openPorts = append(openPorts, sp.Port)
	}

	res := e.probeDevice(ctx, dev.IP, openPorts)

	e.mu.Lock()
	d, ok := e.devices[dev.ID]
	if !ok {
		base := stripNetworkScope(dev.ID)
		if e.activeNetworkKey != "" {
			d, ok = e.devices[e.activeNetworkKey+"/"+base]
		}
	}
	if !ok {
		e.mu.Unlock()
		return res, dev, fmt.Errorf("device disappeared during probe")
	}

	changed := applyProbeResultLocked(d, res)
	out := *d
	e.mu.Unlock()

	if changed {
		e.persistDevice(out)
		e.emitEvent("device_updated", &out)
	}

	return res, out, nil
}

// findDeviceLocked resolves an existing device by MAC, IP fallback, or private-MAC hostname merge.
// Only matches devices on the active network (or legacy unscoped rows). Must hold e.mu.
func (e *Engine) findDeviceLocked(normMAC, ip, hostname string) (dev *Device, found bool, previousMAC string) {
	netKey := e.activeNetworkKey

	if normMAC != "" {
		if id := ScopedDeviceID(netKey, normMAC, ""); id != "" {
			if d, ok := e.devices[id]; ok {
				return d, true, ""
			}
		}
		// Legacy unscoped MAC key from before network scoping.
		if d, ok := e.devices[DeviceID(normMAC, "")]; ok {
			if d.NetworkKey == "" || networkKeysEquivalent(d.NetworkKey, netKey) {
				return d, true, ""
			}
		}
		for _, d := range e.devices {
			if !e.sameNetworkLocked(d) {
				continue
			}
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
		if id := ScopedDeviceID(netKey, "", ip); id != "" {
			if d, ok := e.devices[id]; ok {
				return d, true, ""
			}
		}
		if d, ok := e.devices[DeviceID("", ip)]; ok {
			if d.NetworkKey == "" || networkKeysEquivalent(d.NetworkKey, netKey) {
				return d, true, ""
			}
		}
		for _, d := range e.devices {
			if !e.sameNetworkLocked(d) {
				continue
			}
			if d.IP == ip {
				return d, true, ""
			}
		}
	}

	if normMAC != "" && IsPrivateMAC(normMAC) && hostname != "" {
		want := strings.ToLower(strings.TrimSpace(hostname))
		if !isGenericHostname(want) {
			for _, d := range e.devices {
				if !e.sameNetworkLocked(d) {
					continue
				}
				if d.Hostname == "" {
					continue
				}
				if strings.ToLower(strings.TrimSpace(d.Hostname)) == want {
					return d, true, d.MAC
				}
			}
		}
	}

	return nil, false, ""
}

func (e *Engine) sameNetworkLocked(d *Device) bool {
	if e.activeNetworkKey == "" {
		return true
	}
	if networkKeysEquivalent(d.NetworkKey, e.activeNetworkKey) {
		return true
	}
	if isWiredPlaceholderKey(d.NetworkKey) && ipInCIDR(d.IP, e.activeSubnetCIDR) {
		return true
	}
	if d.NetworkKey == "" {
		return true // legacy — allow merge then stamp network key
	}
	return false
}

func isGenericHostname(hostname string) bool {
	switch strings.ToLower(strings.TrimSpace(hostname)) {
	case "iphone", "ipad", "android", "dhcp", "workstation", "generic", "device",
		"laptop", "computer", "pc", "macbook", "network", "unknown", "host", "local",
		"android-dhcp", "kindle", "galaxy", "home", "lan", "gateway", "router",
		"apple device", "network device", "standard network hardware", "unknown vendor",
		"unknown device",
		"private / randomized mac", "private mac", "randomized mac", "private / randomized mac address":
		return true
	default:
		return false
	}
}

// findBestNameLocked searches existing inventory, previous MACs, mDNS cache, and ARP
// to match the best available hostname/custom name for a device.
// Caller must hold e.mu (at least RLock).
func (e *Engine) findBestNameLocked(target *Device) (name, source string) {
	if target == nil {
		return "", ""
	}
	normMAC := NormalizeMAC(target.MAC)

	// 1. Match by MAC across all known devices (including PreviousMACs)
	if normMAC != "" {
		for _, d := range e.devices {
			if d == target || !e.sameNetworkLocked(d) {
				continue
			}
			matched := (d.MAC != "" && NormalizeMAC(d.MAC) == normMAC)
			if !matched {
				for _, prev := range d.PreviousMACs {
					if NormalizeMAC(prev) == normMAC {
						matched = true
						break
					}
				}
			}
			if !matched && len(target.PreviousMACs) > 0 {
				for _, prev := range target.PreviousMACs {
					if NormalizeMAC(prev) == NormalizeMAC(d.MAC) {
						matched = true
						break
					}
				}
			}
			if matched {
				if d.CustomName != "" {
					return d.CustomName, "custom"
				}
				if d.Hostname != "" && !isGenericLabel(d.Hostname) {
					return d.Hostname, d.NameSource
				}
				if d.Model != "" && !isGenericLabel(d.Model) {
					return d.Model, "model"
				}
			}
		}
	}

	// 2. Match by IP across all known devices on this network
	if target.IP != "" {
		for _, d := range e.devices {
			if d == target || !e.sameNetworkLocked(d) {
				continue
			}
			if d.IP == target.IP {
				if d.CustomName != "" {
					return d.CustomName, "custom"
				}
				if d.Hostname != "" && !isGenericLabel(d.Hostname) {
					return d.Hostname, d.NameSource
				}
				if d.Model != "" && !isGenericLabel(d.Model) {
					return d.Model, "model"
				}
			}
		}
	}

	// 3. Check mDNS resolver cached name (in-memory, non-blocking)
	if e.mdnsResolver != nil && target.IP != "" {
		if cached, src := e.mdnsResolver.CachedName(target.IP); cached != "" && !isGenericLabel(cached) {
			return cached, src
		}
	}

	return "", ""
}

// adoptDeviceMetadataLocked copies non-generic metadata (hostname, custom name, model, vendor, device type)
// from matching records in inventory (matching by MAC, PreviousMACs, or IP).
// Caller must hold e.mu.
func (e *Engine) adoptDeviceMetadataLocked(target *Device) {
	if target == nil {
		return
	}
	normMAC := NormalizeMAC(target.MAC)
	for _, d := range e.devices {
		if d == target || !e.sameNetworkLocked(d) {
			continue
		}
		matched := false
		if normMAC != "" && d.MAC != "" && NormalizeMAC(d.MAC) == normMAC {
			matched = true
		}
		if !matched && normMAC != "" {
			for _, prev := range d.PreviousMACs {
				if NormalizeMAC(prev) == normMAC {
					matched = true
					break
				}
			}
		}
		if !matched && len(target.PreviousMACs) > 0 && d.MAC != "" {
			for _, prev := range target.PreviousMACs {
				if NormalizeMAC(prev) == NormalizeMAC(d.MAC) {
					matched = true
					break
				}
			}
		}
		if !matched && target.IP != "" && d.IP == target.IP {
			matched = true
		}
		if matched {
			if target.IsPrivateMAC {
				if d.MAC != "" && NormalizeMAC(d.MAC) != normMAC {
					target.PreviousMACs = appendUniqueMAC(target.PreviousMACs, d.MAC)
				}
				for _, prev := range d.PreviousMACs {
					target.PreviousMACs = appendUniqueMAC(target.PreviousMACs, prev)
				}
			}
			if target.Hostname == "" || isGenericHostname(target.Hostname) {
				if d.Hostname != "" && !isGenericHostname(d.Hostname) {
					target.Hostname = d.Hostname
					target.NameSource = d.NameSource
				} else if d.Model != "" && !isGenericLabel(d.Model) {
					target.Hostname = d.Model
					target.NameSource = "model"
				}
			}
			if target.CustomName == "" && d.CustomName != "" {
				target.CustomName = d.CustomName
			}
			if (target.Model == "" || isGenericLabel(target.Model)) && d.Model != "" && !isGenericLabel(d.Model) {
				target.Model = d.Model
			}
			if (target.DeviceType == "" || isGenericLabel(target.DeviceType)) && d.DeviceType != "" && !isGenericLabel(d.DeviceType) {
				target.DeviceType = d.DeviceType
				target.Icon = d.Icon
			}
			if (target.Vendor == "" || isGenericLabel(target.Vendor)) && d.Vendor != "" && !isGenericLabel(d.Vendor) {
				target.Vendor = d.Vendor
			}
		}
	}
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
	a1, err1 := netip.ParseAddr(ip1)
	a2, err2 := netip.ParseAddr(ip2)
	if err1 == nil && err2 == nil {
		return a1.Compare(a2) < 0
	}
	return ip1 < ip2
}
