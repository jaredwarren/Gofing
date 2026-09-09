package engine

import "time"

// Settings holds user-configurable runtime preferences.
type Settings struct {
	ScanIntervalSec    int    `json:"scan_interval_sec"`    // Tier 2: full-subnet discovery sweep
	MonitorIntervalSec int    `json:"monitor_interval_sec"` // Tier 1: presence probe of known devices
	EnrichTTLSec       int    `json:"enrich_ttl_sec"`       // Tier 3: re-fingerprint an identified device
	AlertsEnabled      bool   `json:"alerts_enabled"`
	NotifymacOS        bool   `json:"notify_macos"`
	DataDir            string `json:"data_dir,omitempty"`
}

// Bounds for the user-supplied cadences. A value outside its range is clamped
// rather than rejected, so a bad PATCH degrades instead of wedging a tier.
const (
	presenceIntervalMin, presenceIntervalMax   = 3, 300
	discoveryIntervalMin, discoveryIntervalMax = 60, 86400
	enrichTTLMin, enrichTTLMax                 = 60, 604800
)

// clampInterval bounds a user-supplied interval in seconds, falling back to def
// when v is unset (<= 0).
func clampInterval(v, min, max, def int) int {
	if v <= 0 {
		v = def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// presenceInterval is the Tier-1 presence cadence.
func (e *Engine) presenceInterval() time.Duration { return e.monitorInterval() }

// discoveryInterval is the Tier-2 full-sweep cadence.
func (e *Engine) discoveryInterval() time.Duration {
	e.settingsMu.RLock()
	sec := e.settings.ScanIntervalSec
	e.settingsMu.RUnlock()
	return time.Duration(clampInterval(sec, discoveryIntervalMin, discoveryIntervalMax,
		DefaultSettings().ScanIntervalSec)) * time.Second
}

// enrichTTL is how long a fully identified device's fingerprint stays fresh.
func (e *Engine) enrichTTL() time.Duration {
	e.settingsMu.RLock()
	sec := e.settings.EnrichTTLSec
	e.settingsMu.RUnlock()
	return time.Duration(clampInterval(sec, enrichTTLMin, enrichTTLMax,
		DefaultSettings().EnrichTTLSec)) * time.Second
}

// SettingsPatch is a partial update for PUT /api/settings.
type SettingsPatch struct {
	ScanIntervalSec    *int  `json:"scan_interval_sec"`
	MonitorIntervalSec *int  `json:"monitor_interval_sec"`
	EnrichTTLSec       *int  `json:"enrich_ttl_sec"`
	AlertsEnabled      *bool `json:"alerts_enabled"`
	NotifymacOS        *bool `json:"notify_macos"`
}

// DefaultSettings returns built-in defaults: presence every 10s, a full
// discovery sweep every 5 minutes, and identified devices re-fingerprinted
// every 12 hours.
func DefaultSettings() Settings {
	return Settings{
		ScanIntervalSec:    300,
		MonitorIntervalSec: 10,
		EnrichTTLSec:       43200,
		AlertsEnabled:      true,
		NotifymacOS:        true,
	}
}

// Alert is emitted on SSE `alert` when a presence rule fires.
type Alert struct {
	Rule      string `json:"rule"` // new_device | device_offline | device_online
	DeviceID  string `json:"device_id,omitempty"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}
