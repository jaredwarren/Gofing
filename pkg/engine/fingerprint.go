package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/probes"
)

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

	// Roku ECP — owner-assigned name plus exact model. Before TLS: stronger signal.
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
