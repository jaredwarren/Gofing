package engine

import (
	"sync/atomic"
	"testing"
	"time"
)

// alertRecorder counts desktop notifications and SSE alerts by rule.
// notified is atomic because fireAlert dispatches the desktop notification on
// its own goroutine.
type alertRecorder struct {
	notified atomic.Int32
	rules    []string
}

// waitNotified waits briefly for n asynchronous desktop notifications.
func (r *alertRecorder) waitNotified(t *testing.T, n int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if r.notified.Load() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("sent %d desktop notifications, want %d", r.notified.Load(), n)
}

func newAlertEngine(t *testing.T) (*Engine, *alertRecorder) {
	t.Helper()
	eng := New(nil)
	rec := &alertRecorder{}
	eng.SetNotifyFn(func(title, message string) error {
		rec.notified.Add(1)
		return nil
	})
	eng.RegisterEventListener(func(evt string, data interface{}) {
		if evt == "alert" {
			rec.rules = append(rec.rules, data.(Alert).Rule)
		}
	})
	return eng, rec
}

func TestAlertPerRuleToggles(t *testing.T) {
	tests := []struct {
		name       string
		patch      SettingsPatch
		rule       string
		wantAlerts int
	}{
		{"online allowed by default", SettingsPatch{}, AlertRuleDeviceOnline, 1},
		{"offline allowed by default", SettingsPatch{}, AlertRuleDeviceOffline, 1},
		{"online muted", SettingsPatch{AlertOnline: ptr(false)}, AlertRuleDeviceOnline, 0},
		{"offline muted", SettingsPatch{AlertOffline: ptr(false)}, AlertRuleDeviceOffline, 0},
		{"muting online leaves offline alone", SettingsPatch{AlertOnline: ptr(false)}, AlertRuleDeviceOffline, 1},
		{"muting offline leaves online alone", SettingsPatch{AlertOffline: ptr(false)}, AlertRuleDeviceOnline, 1},
		{"new-device is not affected by the presence toggles",
			SettingsPatch{AlertOnline: ptr(false), AlertOffline: ptr(false)}, AlertRuleNewDevice, 1},
		{"master switch overrides everything",
			SettingsPatch{AlertsEnabled: ptr(false), AlertOnline: ptr(true)}, AlertRuleDeviceOnline, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eng, rec := newAlertEngine(t)
			if _, err := eng.UpdateSettings(tc.patch); err != nil {
				t.Fatalf("UpdateSettings: %v", err)
			}
			eng.fireAlert(tc.rule, "dev-1", "something happened")
			if len(rec.rules) != tc.wantAlerts {
				t.Fatalf("fired %d alerts for %s, want %d", len(rec.rules), tc.rule, tc.wantAlerts)
			}
		})
	}
}

func TestAlertDampingSuppressesFlapping(t *testing.T) {
	eng, rec := newAlertEngine(t)
	if _, err := eng.UpdateSettings(SettingsPatch{AlertCooldownSec: ptr(300)}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	// A device flapping on the ~35s cycle we measured in production.
	eng.fireAlert(AlertRuleDeviceOffline, "flapper", "went offline")
	for i := 0; i < 8; i++ {
		eng.fireAlert(AlertRuleDeviceOnline, "flapper", "came back online")
		eng.fireAlert(AlertRuleDeviceOffline, "flapper", "went offline")
	}
	if len(rec.rules) != 1 {
		t.Fatalf("fired %d alerts through the damping window, want 1: %v", len(rec.rules), rec.rules)
	}
	rec.waitNotified(t, 1)
	// And no more than one, once the window has had a chance to let others through.
	time.Sleep(20 * time.Millisecond)
	if got := rec.notified.Load(); got != 1 {
		t.Fatalf("sent %d desktop notifications, want exactly 1", got)
	}
}

func TestAlertDampingIsPerDevice(t *testing.T) {
	eng, rec := newAlertEngine(t)
	if _, err := eng.UpdateSettings(SettingsPatch{AlertCooldownSec: ptr(300)}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	// One noisy device must not mute a different device's first alert.
	eng.fireAlert(AlertRuleDeviceOffline, "noisy", "went offline")
	eng.fireAlert(AlertRuleDeviceOnline, "noisy", "came back online")
	eng.fireAlert(AlertRuleDeviceOffline, "quiet", "went offline")

	if len(rec.rules) != 2 {
		t.Fatalf("fired %d alerts, want 2 (one per device): %v", len(rec.rules), rec.rules)
	}
}

func TestAlertDampingExpires(t *testing.T) {
	eng, rec := newAlertEngine(t)
	if _, err := eng.UpdateSettings(SettingsPatch{AlertCooldownSec: ptr(60)}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	now := time.Now()
	if !eng.allowAlertNow("dev", now) {
		t.Fatal("first alert should pass")
	}
	if eng.allowAlertNow("dev", now.Add(30*time.Second)) {
		t.Fatal("alert inside the window should be damped")
	}
	if !eng.allowAlertNow("dev", now.Add(61*time.Second)) {
		t.Fatal("alert past the window should pass")
	}
	_ = rec
}

func TestAlertDampingDisabled(t *testing.T) {
	eng, rec := newAlertEngine(t)
	if _, err := eng.UpdateSettings(SettingsPatch{AlertCooldownSec: ptr(0)}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	// 0 means no damping, and must not be silently replaced by the default.
	if got := eng.GetSettings().AlertCooldownSec; got != 0 {
		t.Fatalf("AlertCooldownSec = %d, want 0 to survive as 'disabled'", got)
	}
	for i := 0; i < 4; i++ {
		eng.fireAlert(AlertRuleDeviceOffline, "flapper", "went offline")
	}
	if len(rec.rules) != 4 {
		t.Fatalf("fired %d alerts with damping off, want 4", len(rec.rules))
	}
}

func TestAlertNewDeviceDoesNotConsumeDampingWindow(t *testing.T) {
	eng, rec := newAlertEngine(t)
	if _, err := eng.UpdateSettings(SettingsPatch{AlertCooldownSec: ptr(300)}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	// Discovering a device must not silence its first genuine departure.
	eng.fireAlert(AlertRuleNewDevice, "dev-1", "New device")
	eng.fireAlert(AlertRuleDeviceOffline, "dev-1", "went offline")

	if len(rec.rules) != 2 {
		t.Fatalf("fired %d alerts, want both new_device and the first offline: %v",
			len(rec.rules), rec.rules)
	}
}

func TestClampCooldown(t *testing.T) {
	tests := []struct{ in, want int }{
		{0, 0},                                   // disabled stays disabled
		{-5, 0},                                  // negative reads as disabled
		{5, alertCooldownMin},                    // below floor
		{300, 300},                               // in range
		{alertCooldownMax + 1, alertCooldownMax}, // above ceiling
	}
	for _, tc := range tests {
		if got := clampCooldown(tc.in); got != tc.want {
			t.Errorf("clampCooldown(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSettingsDefaultsIncludeAlertControls(t *testing.T) {
	d := DefaultSettings()
	if !d.AlertOnline || !d.AlertOffline {
		t.Fatal("both presence alerts should default on, matching prior behavior")
	}
	if d.AlertCooldownSec != 300 {
		t.Fatalf("AlertCooldownSec default = %d, want 300", d.AlertCooldownSec)
	}
}
