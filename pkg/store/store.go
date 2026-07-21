package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"go.etcd.io/bbolt"
)

const (
	bucketDevices  = "devices"
	bucketEvents   = "events"
	bucketSettings = "settings"
	settingsKey    = "settings"
)

// Event is a persisted presence or alert event (alias of engine.Event).
type Event = engine.Event

// Settings holds user-configurable runtime preferences.
type Settings struct {
	ScanIntervalSec    int    `json:"scan_interval_sec"`
	MonitorIntervalSec int    `json:"monitor_interval_sec"`
	AlertsEnabled      bool   `json:"alerts_enabled"`
	NotifymacOS        bool   `json:"notify_macos"`
	DataDir            string `json:"data_dir,omitempty"`
}

// Store is a BoltDB-backed persistence layer.
type Store struct {
	db *bbolt.DB
}

// DefaultDataDir returns ~/Library/Application Support/Gofing.
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", "GofingData")
	}
	return filepath.Join(home, "Library", "Application Support", "Gofing")
}

// DefaultDBPath returns the default BoltDB file path under DefaultDataDir.
func DefaultDBPath() string {
	return filepath.Join(DefaultDataDir(), "gofing.db")
}

// Open opens (or creates) a BoltDB store at path. Empty path uses DefaultDBPath.
func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	s := &Store{db: db}
	if err := s.initBuckets(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{bucketDevices, bucketEvents, bucketSettings} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveDevice upserts a device keyed by its ID.
func (s *Store) SaveDevice(d engine.Device) error {
	if d.ID == "" {
		return fmt.Errorf("device id is required")
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketDevices))
		return b.Put([]byte(d.ID), payload)
	})
}

// LoadDevices returns all persisted devices.
func (s *Store) LoadDevices() ([]engine.Device, error) {
	var devices []engine.Device
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketDevices))
		return b.ForEach(func(_, v []byte) error {
			var d engine.Device
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			devices = append(devices, d)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if devices == nil {
		devices = []engine.Device{}
	}
	return devices, nil
}

// DeleteDevice removes a device by ID.
func (s *Store) DeleteDevice(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketDevices)).Delete([]byte(id))
	})
}

// AppendEvent stores an event. Empty ID is generated.
func (s *Store) AppendEvent(ev Event) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("%d", ev.Timestamp.UnixNano())
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	// Key sorts lexicographically oldest→newest; ListEvents reverses.
	key := fmt.Sprintf("%020d-%s", ev.Timestamp.UnixNano(), ev.ID)
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketEvents)).Put([]byte(key), payload)
	})
}

// ListEvents returns events newest-first. If deviceID is non-empty, filters to that device.
func (s *Store) ListEvents(deviceID string, limit int) ([]Event, error) {
	var events []Event
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketEvents))
		return b.ForEach(func(_, v []byte) error {
			var ev Event
			if err := json.Unmarshal(v, &ev); err != nil {
				return err
			}
			if deviceID != "" && ev.DeviceID != deviceID {
				return nil
			}
			events = append(events, ev)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	if events == nil {
		events = []Event{}
	}
	return events, nil
}

// GetSettings loads settings, returning defaults when unset.
func (s *Store) GetSettings() (Settings, error) {
	defaults := Settings{
		ScanIntervalSec:    30,
		MonitorIntervalSec: 10,
		AlertsEnabled:      true,
		NotifymacOS:        true,
		DataDir:            DefaultDataDir(),
	}

	var loaded Settings
	var found bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket([]byte(bucketSettings)).Get([]byte(settingsKey))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &loaded)
	})
	if err != nil {
		return defaults, err
	}
	if !found {
		return defaults, nil
	}
	if loaded.ScanIntervalSec == 0 {
		loaded.ScanIntervalSec = defaults.ScanIntervalSec
	}
	if loaded.MonitorIntervalSec == 0 {
		loaded.MonitorIntervalSec = defaults.MonitorIntervalSec
	}
	if loaded.DataDir == "" {
		loaded.DataDir = defaults.DataDir
	}
	return loaded, nil
}

// SetSettings persists settings.
func (s *Store) SetSettings(settings Settings) error {
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketSettings)).Put([]byte(settingsKey), payload)
	})
}
