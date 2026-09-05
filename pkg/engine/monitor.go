package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jaredwarren/Gofing/pkg/scanner"
)

const monitorMissThreshold = 2

// RunMonitor probes known devices between full subnet scans until ctx is cancelled.
func (e *Engine) RunMonitor(ctx context.Context) {
	if ctx == nil {
		return
	}
	timer := time.NewTimer(e.monitorInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.MonitorOnce(ctx)
			timer.Reset(e.monitorInterval())
		}
	}
}

func (e *Engine) monitorInterval() time.Duration {
	e.mu.RLock()
	sec := e.settings.MonitorIntervalSec
	e.mu.RUnlock()
	if sec <= 0 {
		sec = 10
	}
	return time.Duration(sec) * time.Second
}

// MonitorOnce checks reachability of known devices on the active network.
func (e *Engine) MonitorOnce(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.IsScanning() {
		return
	}

	e.mu.Lock()
	if e.isMonitoring || e.isScanning {
		e.mu.Unlock()
		return
	}
	e.isMonitoring = true
	gen := e.scanGen
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.isMonitoring = false
		e.mu.Unlock()
	}()

	type target struct {
		id, ip string
	}
	e.mu.RLock()
	var targets []target
	for _, d := range e.devices {
		if !e.deviceVisibleLocked(d) || d.IP == "" {
			continue
		}
		targets = append(targets, target{id: d.ID, ip: d.IP})
	}
	e.mu.RUnlock()
	if len(targets) == 0 {
		return
	}

	type hit struct {
		id  string
		lat float64
		ok  bool
	}
	results := make([]hit, len(targets))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				results[i] = hit{id: t.id}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			lat, ok := e.probeIP(ctx, t.ip)
			results[i] = hit{id: t.id, lat: lat, ok: ok}
		}(i, t)
	}
	wg.Wait()

	now := time.Now()
	var cameOnline, wentOffline []Device

	e.mu.Lock()
	if e.isScanning || e.scanGen != gen {
		e.mu.Unlock()
		return
	}
	for _, r := range results {
		d, ok := e.devices[r.id]
		if !ok {
			continue
		}
		if r.ok {
			e.missCount[r.id] = 0
			wasOff := !d.IsOnline
			d.IsOnline = true
			d.LastSeen = now
			d.LatencyMs = r.lat
			if wasOff {
				cameOnline = append(cameOnline, *d)
			}
			continue
		}
		e.missCount[r.id]++
		if e.missCount[r.id] >= monitorMissThreshold && d.IsOnline {
			d.IsOnline = false
			wentOffline = append(wentOffline, *d)
		}
	}
	e.mu.Unlock()

	for i := range cameOnline {
		d := cameOnline[i]
		e.persistDevice(d)
		e.recordEvent("online", d.ID, fmt.Sprintf("%s is online", d.DisplayName()))
		e.emitEvent("device_updated", &d)
		e.fireAlert("device_online", d.ID, fmt.Sprintf("%s came back online", d.DisplayName()))
	}
	for i := range wentOffline {
		d := wentOffline[i]
		e.persistDevice(d)
		e.recordEvent("offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
		e.emitEvent("device_offline", d)
		e.emitEvent("device_updated", d)
		e.fireAlert("device_offline", d.ID, fmt.Sprintf("%s went offline", d.DisplayName()))
	}
}

func (e *Engine) probeIP(ctx context.Context, ip string) (float64, bool) {
	if e.probeFn != nil {
		return e.probeFn(ctx, ip)
	}
	return scanner.ProbeIP(ctx, ip)
}

func (e *Engine) loadSettings() {
	if e.persist == nil {
		return
	}
	s, err := e.persist.GetSettings()
	if err != nil {
		return
	}
	if s.MonitorIntervalSec == 0 {
		s.MonitorIntervalSec = 10
	}
	if s.ScanIntervalSec == 0 {
		s.ScanIntervalSec = 30
	}
	e.mu.Lock()
	e.settings = s
	e.mu.Unlock()
}

// GetSettings returns a copy of current runtime settings.
func (e *Engine) GetSettings() Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

// UpdateSettings applies a partial settings patch and persists it.
func (e *Engine) UpdateSettings(patch SettingsPatch) (Settings, error) {
	e.mu.Lock()
	if patch.ScanIntervalSec != nil && *patch.ScanIntervalSec > 0 {
		e.settings.ScanIntervalSec = *patch.ScanIntervalSec
	}
	if patch.MonitorIntervalSec != nil && *patch.MonitorIntervalSec > 0 {
		e.settings.MonitorIntervalSec = *patch.MonitorIntervalSec
	}
	if patch.AlertsEnabled != nil {
		e.settings.AlertsEnabled = *patch.AlertsEnabled
	}
	if patch.NotifymacOS != nil {
		e.settings.NotifymacOS = *patch.NotifymacOS
	}
	out := e.settings
	e.mu.Unlock()

	if e.persist != nil {
		if err := e.persist.SetSettings(out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (e *Engine) fireAlert(rule, deviceID, message string) {
	e.mu.RLock()
	enabled := e.settings.AlertsEnabled
	desktop := e.settings.NotifymacOS
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
