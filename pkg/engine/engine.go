package engine

import (
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
}

// New returns an initialized Engine.
func New() *Engine {
	return &Engine{
		devices:      make(map[string]*Device),
		netScanner:   scanner.New(),
		mdnsResolver: mdns.New(),
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
	e.mu.Lock()
	for _, dev := range e.devices {
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
				e.upsertDevice(raw, details, macVendor, now)
			}
		}()
	}

	wg.Wait()

	finalList := e.GetDevices()
	e.emitEvent("scan_complete", map[string]interface{}{
		"total_devices": len(finalList),
		"timestamp":     now.Format(time.RFC3339),
	})

	return finalList, nil
}

// upsertDevice merges a scanned host into inventory using stable identity rules.
// Caller must NOT hold e.mu.
func (e *Engine) upsertDevice(raw scanner.RawDevice, details mdns.DeviceDetails, macVendor string, now time.Time) {
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
		e.mu.Unlock()
		e.emitEvent("device_found", newDev)
		return
	}

	// IP change for known MAC (or hostname merge): keep ID and FirstSeen.
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

		// Promote ip:-based identity to MAC identity only. MAC rotations keep the original ID.
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
	if details.DeviceType != "" {
		existing.DeviceType = details.DeviceType
		existing.Icon = details.Icon
		existing.Model = details.Model
	}
	existing.Services = details.Services

	e.mu.Unlock()
	e.emitEvent("device_updated", existing)
}

// findDeviceLocked resolves an existing device by MAC, IP fallback, or private-MAC hostname merge.
// Must be called with e.mu held.
func (e *Engine) findDeviceLocked(normMAC, ip, hostname string) (dev *Device, found bool, previousMAC string) {
	// 1. MAC match
	if normMAC != "" {
		if d, ok := e.devices[DeviceID(normMAC, "")]; ok {
			return d, true, ""
		}
		// Also scan in case ID was ip:-based but MAC field matches.
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

	// 2. IP fallback key
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

	// 3. Private MAC rotation: merge on exact hostname (case-insensitive).
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
