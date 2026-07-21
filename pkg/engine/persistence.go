package engine

import (
	"strings"
	"time"
)

// Event is a presence or alert event persisted via Persistence.
type Event struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // online|offline|found|updated|alert|...
	DeviceID  string    `json:"device_id,omitempty"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// Persistence is the engine's storage dependency. Implemented by pkg/store.Store.
// Defined here so engine does not import store (store already imports engine).
type Persistence interface {
	SaveDevice(d Device) error
	LoadDevices() ([]Device, error)
	AppendEvent(ev Event) error
	ListEvents(deviceID string, limit int) ([]Event, error)
}

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
		"unknown vendor", "generic", "device":
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
