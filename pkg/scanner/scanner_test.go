package scanner

import (
	"testing"
)

func TestFormatMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"34:58:40:a:b:c", "34:58:40:0A:0B:0C"},
		{"0:11:22:33:44:55", "00:11:22:33:44:55"},
		{"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"},
	}

	for _, tt := range tests {
		got := formatMAC(tt.input)
		if got != tt.expected {
			t.Errorf("formatMAC(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/29")
	if err != nil {
		t.Fatalf("expandCIDR failed: %v", err)
	}

	// /29 has 8 addresses total (192.168.1.0 to 192.168.1.7). Minus net & broadcast = 6 host IPs.
	if len(ips) != 6 {
		t.Errorf("expected 6 host IPs, got %d", len(ips))
	}

	if ips[0] != "192.168.1.1" || ips[len(ips)-1] != "192.168.1.6" {
		t.Errorf("unexpected IP range: %v", ips)
	}
}

func TestParsePingLatency(t *testing.T) {
	sampleOutput := "64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=2.418 ms"
	lat := parsePingLatency(sampleOutput)
	if lat != 2.418 {
		t.Errorf("expected 2.418, got %f", lat)
	}
}
