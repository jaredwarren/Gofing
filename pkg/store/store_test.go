package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
)

func TestSaveLoadDevices(t *testing.T) {
	s := openTemp(t)
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	dev := engine.Device{
		ID:        "AA:BB:CC:DD:EE:FF",
		IP:        "192.168.1.10",
		MAC:       "AA:BB:CC:DD:EE:FF",
		Hostname:  "test-host",
		IsOnline:  true,
		FirstSeen: now,
		LastSeen:  now,
	}
	if err := s.SaveDevice(dev); err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	loaded, err := s.LoadDevices()
	if err != nil {
		t.Fatalf("LoadDevices: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 device, got %d", len(loaded))
	}
	if loaded[0].ID != dev.ID || loaded[0].IP != dev.IP || loaded[0].Hostname != dev.Hostname {
		t.Fatalf("round-trip mismatch: %+v", loaded[0])
	}
}

func TestDeleteDevice(t *testing.T) {
	s := openTemp(t)
	defer s.Close()

	_ = s.SaveDevice(engine.Device{ID: "AA:BB:CC:DD:EE:FF", IP: "10.0.0.1"})
	if err := s.DeleteDevice("AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	loaded, err := s.LoadDevices()
	if err != nil {
		t.Fatalf("LoadDevices: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(loaded))
	}
}

func TestAppendAndListEvents(t *testing.T) {
	s := openTemp(t)
	defer s.Close()

	base := time.Now().UTC().Add(-time.Minute)
	events := []Event{
		{Type: "found", DeviceID: "dev-a", Message: "oldest", Timestamp: base},
		{Type: "online", DeviceID: "dev-a", Message: "middle", Timestamp: base.Add(10 * time.Second)},
		{Type: "offline", DeviceID: "dev-b", Message: "other", Timestamp: base.Add(20 * time.Second)},
		{Type: "online", DeviceID: "dev-a", Message: "newest", Timestamp: base.Add(30 * time.Second)},
	}
	for _, ev := range events {
		if err := s.AppendEvent(ev); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}

	all, err := s.ListEvents("", 0)
	if err != nil {
		t.Fatalf("ListEvents all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 events, got %d", len(all))
	}
	if all[0].Message != "newest" {
		t.Fatalf("expected newest first, got %q", all[0].Message)
	}

	limited, err := s.ListEvents("", 2)
	if err != nil {
		t.Fatalf("ListEvents limit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected limit 2, got %d", len(limited))
	}

	filtered, err := s.ListEvents("dev-a", 10)
	if err != nil {
		t.Fatalf("ListEvents filter: %v", err)
	}
	if len(filtered) != 3 {
		t.Fatalf("expected 3 events for dev-a, got %d", len(filtered))
	}
	for _, ev := range filtered {
		if ev.DeviceID != "dev-a" {
			t.Fatalf("unexpected device id %q", ev.DeviceID)
		}
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := openTemp(t)
	defer s.Close()

	defaults, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings defaults: %v", err)
	}
	if defaults.ScanIntervalSec != 30 || !defaults.AlertsEnabled {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}

	want := Settings{
		ScanIntervalSec:    60,
		MonitorIntervalSec: 5,
		AlertsEnabled:      false,
		NotifymacOS:        true,
		DataDir:            "/tmp/gofing-test",
	}
	if err := s.SetSettings(want); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	got, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got != want {
		t.Fatalf("settings mismatch: got %+v want %+v", got, want)
	}
}

func TestDefaultPaths(t *testing.T) {
	dir := DefaultDataDir()
	if dir == "" {
		t.Fatal("DefaultDataDir empty")
	}
	db := DefaultDBPath()
	if filepath.Base(db) != "gofing.db" {
		t.Fatalf("unexpected db path %q", db)
	}
	if filepath.Dir(db) != dir {
		t.Fatalf("db path not under data dir: %q vs %q", db, dir)
	}
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}
