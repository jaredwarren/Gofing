package engine

// Settings holds user-configurable runtime preferences.
type Settings struct {
	ScanIntervalSec    int    `json:"scan_interval_sec"`
	MonitorIntervalSec int    `json:"monitor_interval_sec"`
	AlertsEnabled      bool   `json:"alerts_enabled"`
	NotifymacOS        bool   `json:"notify_macos"`
	DataDir            string `json:"data_dir,omitempty"`
}

// SettingsPatch is a partial update for PUT /api/settings.
type SettingsPatch struct {
	ScanIntervalSec    *int  `json:"scan_interval_sec"`
	MonitorIntervalSec *int  `json:"monitor_interval_sec"`
	AlertsEnabled      *bool `json:"alerts_enabled"`
	NotifymacOS        *bool `json:"notify_macos"`
}

// DefaultSettings returns built-in defaults (10s monitor, alerts on).
func DefaultSettings() Settings {
	return Settings{
		ScanIntervalSec:    30,
		MonitorIntervalSec: 10,
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
