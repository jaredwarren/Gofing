package mdns

import (
	"testing"
)

func TestClassifyDevice(t *testing.T) {
	tests := []struct {
		hostname string
		vendor   string
		services []string
		expected string
		icon     string
	}{
		{"Jareds-MacBook-Pro.local", "Apple, Inc.", nil, "Computer", "laptop"},
		{"Living-Room-Sonos", "Sonos, Inc.", nil, "Smart Speaker", "speaker"},
		{"AppleTV-Living-Room", "Apple, Inc.", nil, "Smart TV", "tv"},
		{"Printer-HP", "HP Inc.", []string{"Printer"}, "Printer", "printer"},
		{"", "Espressif Inc.", nil, "Smart Home / IoT", "iot"},
	}

	for _, tt := range tests {
		devType, icon, _ := classifyDevice(tt.hostname, tt.vendor, tt.services, "")
		if devType != tt.expected {
			t.Errorf("classifyDevice(%q, %q) type = %q; want %q", tt.hostname, tt.vendor, devType, tt.expected)
		}
		if icon != tt.icon {
			t.Errorf("classifyDevice(%q, %q) icon = %q; want %q", tt.hostname, tt.vendor, icon, tt.icon)
		}
	}
}

func TestResolveDeviceHostComputer(t *testing.T) {
	r := New()
	details := r.ResolveDevice("192.168.0.72", "3A:45:DB:15:44:3D", "Apple, Inc.", false, "Jared’s MacBook Pro  M4")
	if details.Hostname != "Jared’s MacBook Pro  M4" {
		t.Errorf("expected hostname Jared’s MacBook Pro  M4, got %q", details.Hostname)
	}
}
