package engine

import (
	"fmt"
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

// Engine coordinates scanning, fingerprinting, and state management.
type Engine struct {
	mu           sync.RWMutex
	devices      map[string]*Device // keyed by stable Device.ID
	netScanner   *scanner.Scanner
	mdnsResolver *mdns.Resolver
	listeners    []EventFunc
	isScanning   bool
	persist      Persistence
}

// New returns an initialized Engine. persist may be nil (in-memory only).
func New(persist Persistence) *Engine {
	e := &Engine{
		devices:      make(map[string]*Device),
		netScanner:   scanner.New(),
		mdnsResolver: mdns.New(),
		persist:      persist,
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
		dev.IsOnline = false
	}
	e.mu.Unlock()

	var wg sync.WaitGroup
	deviceChan := make(chan scanner.RawDevice, len(rawDevices))
	for _, raw := range rawDevices {
		deviceChan <- raw
	}
	close(deviceChan)

	concurrency := 32
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

				details := e.mdnsResolver.ResolveDevice(raw.IP, raw.MAC, macVendor, isGateway, hostCompName)
				e.upsertDevice(raw, details, macVendor, now, wasOnline)
			}
		}()
	}

	wg.Wait()

	// Persist offline transitions and final offline state.
	e.mu.Lock()
	var wentOffline []Device
	var allDevices []Device
	for id, dev := range e.devices {
		allDevices = append(allDevices, *dev)
		if wasOnline[id] && !dev.IsOnline {
			wentOffline = append(wentOffline, *dev)
		}
	}
	e.mu.Unlock()

	for _, d := range wentOffline {
		e.recordEvent("offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
		e.emitEvent("device_offline", d)
		e.emitEvent("device_updated", d) // keep UI clients that only listen for updates in sync
	}
	for _, d := range allDevices {
		e.persistDevice(d)
	}

	finalList := e.GetDevices()
	e.emitEvent("scan_complete", map[string]interface{}{
		"total_devices": len(finalList),
		"timestamp":     now.Format(time.RFC3339),
	})

	return finalList, nil
}

// upsertDevice merges a scanned host into inventory using stable identity rules.
// Caller must NOT hold e.mu.
func (e *Engine) upsertDevice(raw scanner.RawDevice, details mdns.DeviceDetails, macVendor string, now time.Time, wasOnline map[string]bool) {
	normMAC := NormalizeMAC(raw.MAC)
	private := IsPrivateMAC(normMAC)

	e.mu.Lock()

	existing, found, previousMAC := e.findDeviceLocked(normMAC, raw.IP, details.Hostname)

	if !found {
		id := DeviceID(normMAC, raw.IP)
		newDev := &Device{
			ID:           id,
			IP:           raw.IP,
			MAC:          normMAC,
			Vendor:       macVendor,
			Hostname:     details.Hostname,
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
		out := *newDev
		e.mu.Unlock()

		e.persistDevice(out)
		e.recordEvent("found", out.ID, fmt.Sprintf("Discovered %s (%s)", out.DisplayName(), out.IP))
		e.emitEvent("device_found", &out)
		return
	}

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
				existing.ID = newID
				e.devices[newID] = existing
			}
		}
	}

	if details.Hostname != "" {
		existing.Hostname = details.Hostname
	}
	// Auto-fingerprint must not overwrite user overrides; DeviceType still updates underneath.
	if details.DeviceType != "" {
		existing.DeviceType = details.DeviceType
		existing.Icon = details.Icon
		existing.Model = details.Model
	}
	existing.Services = details.Services

	out := *existing
	e.mu.Unlock()

	e.persistDevice(out)
	if cameOnline {
		e.recordEvent("online", out.ID, fmt.Sprintf("%s is online", out.DisplayName()))
	}
	e.emitEvent("device_updated", &out)
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
