package engine

import (
	"log/slog"
	"time"

	"github.com/jaredwarren/Gofing/pkg/dhcp"
	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/oui"
)

// DHCPImportResult is the outcome of applying router DHCP leases.
type DHCPImportResult struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

// ImportDHCPLeases upserts router DHCP client-list rows by MAC.
// Names use NameSourceDHCP. Leases never mark a device online — presence stays
// with ARP/scan. Sleeping devices therefore appear named but offline.
func (e *Engine) ImportDHCPLeases(leases []dhcp.Lease) DHCPImportResult {
	var res DHCPImportResult
	if len(leases) == 0 {
		return res
	}

	now := time.Now()
	var foundEvents []Device
	var updatedEvents []Device
	var toSave []Device

	e.mu.Lock()
	netKey := e.activeNetworkKey

	for _, lease := range leases {
		mac := NormalizeMAC(lease.MAC)
		if mac == "" || !looksLikeMAC(mac) {
			res.Skipped++
			continue
		}
		host, _ := mdns.PreferHostname("", mdns.NameSourceNone, lease.Hostname, mdns.NameSourceDHCP)
		if host == "" {
			res.Skipped++
			continue
		}

		existing, found, _ := e.findDeviceLocked(mac, lease.IP, host)
		if !found {
			id := ScopedDeviceID(netKey, mac, lease.IP)
			dev := &Device{
				ID:           id,
				NetworkKey:   netKey,
				IP:           lease.IP,
				MAC:          mac,
				Vendor:       oui.LookupVendor(mac),
				Hostname:     host,
				NameSource:   mdns.NameSourceDHCP,
				DeviceType:   "Network Device",
				Icon:         "device",
				Model:        host,
				IsOnline:     false,
				IsPrivateMAC: IsPrivateMAC(mac),
				FirstSeen:    now,
				LastSeen:     now,
			}
			e.devices[id] = dev
			res.Created++
			cp := *dev
			toSave = append(toSave, cp)
			foundEvents = append(foundEvents, cp)
			continue
		}

		beforeHost := existing.Hostname
		beforeSrc := existing.NameSource
		beforeIP := existing.IP
		existing.Hostname, existing.NameSource = mdns.PreferHostname(
			existing.Hostname, existing.NameSource, host, mdns.NameSourceDHCP,
		)
		if lease.IP != "" {
			existing.IP = lease.IP
		}
		if existing.NetworkKey == "" && netKey != "" {
			existing.NetworkKey = netKey
		}
		changed := existing.Hostname != beforeHost || existing.NameSource != beforeSrc || existing.IP != beforeIP
		if !changed {
			continue
		}
		res.Updated++
		cp := *existing
		toSave = append(toSave, cp)
		updatedEvents = append(updatedEvents, cp)
	}
	e.mu.Unlock()

	if e.persist != nil && len(toSave) > 0 {
		if err := e.persist.SaveDevices(toSave); err != nil {
			slog.Error("DHCP import save failed", "error", err)
			for _, d := range toSave {
				e.persistDevice(d)
			}
		}
	}

	for i := range foundEvents {
		d := foundEvents[i]
		e.recordEvent("found", d.ID, "DHCP lease "+d.DisplayName())
		e.emitEvent("device_found", &d)
	}
	for i := range updatedEvents {
		d := updatedEvents[i]
		e.emitEvent("device_updated", &d)
	}
	return res
}
