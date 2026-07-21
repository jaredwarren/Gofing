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
		{"AMYS-MBP", "Apple, Inc.", nil, "Computer", "laptop"},
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

func TestResolveDeviceUsesARPHostname(t *testing.T) {
	r := New()
	details := r.ResolveDevice("192.168.0.142", "8C:85:90:24:10:B7", "Apple, Inc.", false, "", "amys-mbp.local")
	if details.Hostname != "amys-mbp" {
		t.Fatalf("hostname=%q want amys-mbp", details.Hostname)
	}
	if details.NameSource != NameSourceARP {
		t.Fatalf("name_source=%q want %q", details.NameSource, NameSourceARP)
	}
	if details.DeviceType != "Computer" {
		t.Fatalf("device type=%q want Computer", details.DeviceType)
	}
}

func TestResolveDeviceHostComputer(t *testing.T) {
	r := New()
	details := r.ResolveDevice("192.168.0.72", "3A:45:DB:15:44:3D", "Apple, Inc.", false, "Jared’s MacBook Pro  M4", "")
	if details.Hostname != "Jared’s MacBook Pro  M4" {
		t.Errorf("expected hostname Jared’s MacBook Pro  M4, got %q", details.Hostname)
	}
}

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Record", ""},
		{"WORKGROUP", ""},
		{"AMYS-MBP", "AMYS-MBP"},
		{"Jared's MacBook", "Jared's MacBook"},
		{"AMYS-MBP.local", "AMYS-MBP.local"},
		{"\x80\x94\x00\x01$", ""},          // NetBIOS-ish binary garbage
		{"\x00\x01\x02", ""},
		{"���$�", ""},                     // replacement-char junk
		{"$", ""},
		{"A", ""}, // too short / not enough alnum
		{"", ""},
	}

	for _, tt := range tests {
		got := SanitizeHostname(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeHostname(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizeResolvedName(t *testing.T) {
	if got := normalizeResolvedName("AMYS-MBP.local."); got != "AMYS-MBP" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeResolvedName("AMYS-MBP"); got != "AMYS-MBP" {
		t.Fatalf("got %q", got)
	}
}

func TestIsNetBIOSStyleName(t *testing.T) {
	if !isNetBIOSStyleName("AMYS-MBP") {
		t.Error("AMYS-MBP should be valid NetBIOS style")
	}
	if isNetBIOSStyleName("Amy's Mac") {
		t.Error("apostrophe names are not NetBIOS style")
	}
}
