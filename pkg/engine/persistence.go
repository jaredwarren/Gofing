package engine

import (
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
	SaveDevices(devices []Device) error
	LoadDevices() ([]Device, error)
	DeleteDevice(id string) error
	AppendEvent(ev Event) error
	ListEvents(deviceID string, limit int) ([]Event, error)
	GetSettings() (Settings, error)
	SetSettings(Settings) error
}
