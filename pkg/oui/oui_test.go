package oui

import (
	"testing"
)

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"00:1C:42:11:22:33", "Parallels (Virtual Mac)"},
		{"DC:A6:32:00:11:22", "Raspberry Pi Trading Ltd"},
		{"00:0E:58:AA:BB:CC", "Sonos, Inc."},
		{"00:17:88:99:88:77", "Philips Lighting / Hue"},
		{"00:00:0C:12:34:56", "Cisco Systems"},
		{"54:AF:97:14:CF:7C", "TP-Link Technologies"},
		{"3A:45:DB:15:44:3D", "Private / Randomized MAC"},
		{"AE:35:05:49:5A:0C", "Private / Randomized MAC"},
		{"", "Unknown Vendor"},
	}

	for _, tt := range tests {
		got := LookupVendor(tt.mac)
		if got != tt.expected {
			t.Errorf("LookupVendor(%q) = %q; want %q", tt.mac, got, tt.expected)
		}
	}
}

func TestIsRandomizedMAC(t *testing.T) {
	if !isRandomizedMAC("3A45DB15443D") {
		t.Errorf("expected 3A:45:DB... to be randomized")
	}
	if !isRandomizedMAC("AE3505495A0C") {
		t.Errorf("expected AE:35:05... to be randomized")
	}
	if isRandomizedMAC("001C42112233") {
		t.Errorf("expected 00:1C:42... NOT to be randomized")
	}
}
