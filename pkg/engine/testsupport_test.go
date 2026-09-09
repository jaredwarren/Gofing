package engine

import (
	"sort"
	"sync"

	"github.com/jaredwarren/Gofing/pkg/network"
)

// memPersist is an in-memory Persistence for tests. It records call counts so
// tests can assert on batching (one transaction per pass, not one per device).
type memPersist struct {
	mu sync.Mutex

	devices  map[string]Device
	events   []Event
	settings Settings
	hasSet   bool

	saveDeviceCalls  int
	saveDevicesCalls int
	setSettingsCalls int
}

func newMemPersist(seed ...Device) *memPersist {
	m := &memPersist{devices: make(map[string]Device)}
	for _, d := range seed {
		m.devices[d.ID] = d
	}
	return m
}

func (m *memPersist) SaveDevice(d Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveDeviceCalls++
	m.devices[d.ID] = d
	return nil
}

func (m *memPersist) SaveDevices(devices []Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveDevicesCalls++
	for _, d := range devices {
		m.devices[d.ID] = d
	}
	return nil
}

func (m *memPersist) LoadDevices() ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memPersist) DeleteDevice(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.devices, id)
	return nil
}

func (m *memPersist) AppendEvent(ev Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memPersist) ListEvents(deviceID string, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
		if deviceID == "" || m.events[i].DeviceID == deviceID {
			out = append(out, m.events[i])
		}
	}
	return out, nil
}

func (m *memPersist) GetSettings() (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasSet {
		return DefaultSettings(), nil
	}
	return m.settings, nil
}

func (m *memPersist) SetSettings(s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setSettingsCalls++
	m.settings = s
	m.hasSet = true
	return nil
}

// stored returns a snapshot of a persisted device.
func (m *memPersist) stored(id string) (Device, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	return d, ok
}

func (m *memPersist) counts() (saveDevice, saveDevices, setSettings int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveDeviceCalls, m.saveDevicesCalls, m.setSettingsCalls
}

// netInfoFor builds a minimal active-network descriptor for tests.
func netInfoFor(subnet, gateway string) network.Info {
	return network.Info{
		InterfaceName: "en0",
		IP:            "192.168.0.2",
		MAC:           "AA:BB:CC:00:00:01",
		SubnetCIDR:    subnet,
		GatewayIP:     gateway,
		SSID:          "test-ssid",
		ComputerName:  "test-mac",
	}
}
