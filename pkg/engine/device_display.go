package engine

import "strings"

// DisplayName returns the preferred user-facing name.
func (d Device) DisplayName() string {
	if d.CustomName != "" {
		return d.CustomName
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	if d.Model != "" && !isGenericLabel(d.Model) {
		return d.Model
	}
	if d.Vendor != "" && !isGenericLabel(d.Vendor) {
		return d.Vendor
	}
	if d.IP != "" {
		return d.IP
	}
	return "Unknown Device"
}

func isGenericLabel(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "apple device", "generic device", "network device", "standard network hardware",
		"unknown vendor", "generic", "device", "unknown", "unknown device",
		"private / randomized mac", "private mac", "randomized mac", "private / randomized mac address":
		return true
	default:
		return false
	}
}

// DisplayType returns the preferred device type (override wins).
func (d Device) DisplayType() string {
	if d.DeviceTypeOverride != "" {
		return d.DeviceTypeOverride
	}
	if d.DeviceType != "" {
		return d.DeviceType
	}
	return "Generic Device"
}
