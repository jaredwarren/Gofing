package engine

import "time"

// Settings holds user-configurable runtime preferences.
type Settings struct {
	ScanIntervalSec    int  `json:"scan_interval_sec"`    // Tier 2: full-subnet discovery sweep
	MonitorIntervalSec int  `json:"monitor_interval_sec"` // Tier 1: presence probe of known devices
	EnrichTTLSec       int  `json:"enrich_ttl_sec"`       // Tier 3: re-fingerprint an identified device
	AlertsEnabled      bool `json:"alerts_enabled"`       // master switch for all alerts
	AlertOnline        bool `json:"alert_online"`         // notify when a device comes back online
	AlertOffline       bool `json:"alert_offline"`        // notify when a device goes offline
	// AlertCooldownSec is the minimum gap between two alerts about the same
	// device. A device whose reachability is genuinely marginal will still flip
	// state; this bounds how often that is allowed to interrupt the user.
	// 0 disables the damping.
	AlertCooldownSec int    `json:"alert_cooldown_sec"`
	NotifymacOS      bool   `json:"notify_macos"`
	RemoteOUILookup  bool   `json:"remote_oui_lookup"` // allow maclookup.app (OUI prefix only)
	DataDir          string `json:"data_dir,omitempty"`
}

// Bounds for the user-supplied cadences. A value outside its range is clamped
// rather than rejected, so a bad PATCH degrades instead of wedging a tier.
const (
	presenceIntervalMin, presenceIntervalMax   = 3, 300
	discoveryIntervalMin, discoveryIntervalMax = 60, 86400
	enrichTTLMin, enrichTTLMax                 = 60, 604800

	// Alert damping bounds. Zero is meaningful here — it disables damping — so
	// this range applies only to non-zero values.
	alertCooldownMin, alertCooldownMax = 10, 86400
)

// clampCooldown bounds the alert damping window. Unlike clampInterval, 0 is a
// valid setting meaning "no damping", so it is passed through rather than
// replaced by the default.
func clampCooldown(v int) int {
	if v <= 0 {
		return 0
	}
	if v < alertCooldownMin {
		return alertCooldownMin
	}
	if v > alertCooldownMax {
		return alertCooldownMax
	}
	return v
}

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

// alertCooldown is the minimum gap between two alerts about one device.
func (e *Engine) alertCooldown() time.Duration {
	e.settingsMu.RLock()
	sec := e.settings.AlertCooldownSec
	e.settingsMu.RUnlock()
	return time.Duration(clampCooldown(sec)) * time.Second
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
	AlertOnline        *bool `json:"alert_online"`
	AlertOffline       *bool `json:"alert_offline"`
	AlertCooldownSec   *int  `json:"alert_cooldown_sec"`
	NotifymacOS        *bool `json:"notify_macos"`
	RemoteOUILookup    *bool `json:"remote_oui_lookup"`
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
		AlertOnline:        true,
		AlertOffline:       true,
		AlertCooldownSec:   300,
		NotifymacOS:        true,
		RemoteOUILookup:    true,
	}
}

// Alert is emitted on SSE `alert` when a presence rule fires.
type Alert struct {
	Rule      string `json:"rule"` // new_device | device_offline | device_online
	DeviceID  string `json:"device_id,omitempty"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}
