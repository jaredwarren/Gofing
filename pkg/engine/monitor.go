package engine

import (
	"context"
	"log/slog"
	"time"
)

// RunMonitor runs the presence tier until ctx is cancelled.
//
// Deprecated: prefer StartTiers, which runs presence, discovery and enrichment
// together. Retained because it is the shape existing callers expect.
func (e *Engine) RunMonitor(ctx context.Context) {
	if ctx == nil {
		return
	}
	e.presenceLoop(ctx)
}

// MonitorOnce runs a single presence pass. It no longer defers to a running
// scan: presence is Tier 1 and must answer on its own cadence.
func (e *Engine) MonitorOnce(ctx context.Context) {
	e.PresenceOnce(ctx, e.currentNetInfo(30*time.Second))
}

func (e *Engine) monitorInterval() time.Duration {
	e.settingsMu.RLock()
	sec := e.settings.MonitorIntervalSec
	e.settingsMu.RUnlock()
	return time.Duration(clampInterval(sec, presenceIntervalMin, presenceIntervalMax,
		DefaultSettings().MonitorIntervalSec)) * time.Second
}

func (e *Engine) loadSettings() {
	if e.persist == nil {
		return
	}
	s, err := e.persist.GetSettings()
	if err != nil {
		return
	}
	defaults := DefaultSettings()
	if s.MonitorIntervalSec == 0 {
		s.MonitorIntervalSec = defaults.MonitorIntervalSec
	}
	if s.ScanIntervalSec == 0 {
		s.ScanIntervalSec = defaults.ScanIntervalSec
	}
	if s.EnrichTTLSec == 0 {
		s.EnrichTTLSec = defaults.EnrichTTLSec
	}
	// ScanIntervalSec used to be stored but unread, so existing databases hold
	// the old 30s scan cadence. It now drives the full-subnet sweep, where 30s
	// would be far too aggressive.
	migrated := false
	if s.ScanIntervalSec < discoveryIntervalMin {
		slog.Info("migrating stored scan interval to the discovery sweep cadence",
			"was_sec", s.ScanIntervalSec, "now_sec", defaults.ScanIntervalSec)
		s.ScanIntervalSec = defaults.ScanIntervalSec
		migrated = true
	}

	e.settingsMu.Lock()
	e.settings = s
	e.settingsMu.Unlock()

	if migrated {
		if err := e.persist.SetSettings(s); err != nil {
			slog.Warn("failed to persist migrated scan interval", "error", err)
		}
	}
}

// GetSettings returns a copy of current runtime settings.
func (e *Engine) GetSettings() Settings {
	e.settingsMu.RLock()
	defer e.settingsMu.RUnlock()
	return e.settings
}

// UpdateSettings applies a partial settings patch and persists it.
func (e *Engine) UpdateSettings(patch SettingsPatch) (Settings, error) {
	defaults := DefaultSettings()

	e.settingsMu.Lock()
	if patch.ScanIntervalSec != nil && *patch.ScanIntervalSec > 0 {
		e.settings.ScanIntervalSec = clampInterval(*patch.ScanIntervalSec,
			discoveryIntervalMin, discoveryIntervalMax, defaults.ScanIntervalSec)
	}
	if patch.MonitorIntervalSec != nil && *patch.MonitorIntervalSec > 0 {
		e.settings.MonitorIntervalSec = clampInterval(*patch.MonitorIntervalSec,
			presenceIntervalMin, presenceIntervalMax, defaults.MonitorIntervalSec)
	}
	if patch.EnrichTTLSec != nil && *patch.EnrichTTLSec > 0 {
		e.settings.EnrichTTLSec = clampInterval(*patch.EnrichTTLSec,
			enrichTTLMin, enrichTTLMax, defaults.EnrichTTLSec)
	}
	if patch.AlertsEnabled != nil {
		e.settings.AlertsEnabled = *patch.AlertsEnabled
	}
	if patch.NotifymacOS != nil {
		e.settings.NotifymacOS = *patch.NotifymacOS
	}
	out := e.settings
	e.settingsMu.Unlock()

	if e.persist != nil {
		if err := e.persist.SetSettings(out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (e *Engine) fireAlert(rule, deviceID, message string) {
	e.settingsMu.RLock()
	enabled := e.settings.AlertsEnabled
	desktop := e.settings.NotifymacOS
	e.settingsMu.RUnlock()

	e.mu.RLock()
	notifyFn := e.notifyFn
	e.mu.RUnlock()
	if !enabled {
		return
	}
	alert := Alert{
		Rule:      rule,
		DeviceID:  deviceID,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	e.recordEvent("alert", deviceID, message)
	e.emitEvent("alert", alert)
	if desktop && notifyFn != nil {
		go func() {
			_ = notifyFn("Gofing", message)
		}()
	}
}

// ListEvents returns newest-first events. Empty deviceID returns the global feed.
func (e *Engine) ListEvents(deviceID string, limit int) ([]Event, error) {
	if e.persist == nil {
		return []Event{}, nil
	}
	if limit <= 0 {
		limit = 100
	}
	return e.persist.ListEvents(deviceID, limit)
}
