package scanner

import (
	"testing"
	"time"
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

func TestMergeProbeAndARPIncludesCompleteARP(t *testing.T) {
	now := time.Now()
	ping := map[string]float64{
		"192.168.0.1": 1.2,
	}
	arp := map[string]RawDevice{
		"192.168.0.1":   {IP: "192.168.0.1", MAC: "AA:BB:CC:DD:EE:01", Iface: "en0", Hostname: "router.local"},
		"192.168.0.132": {IP: "192.168.0.132", MAC: "28:CD:C1:01:43:34", Iface: "en0"}, // ICMP-silent, L2 present
		"10.8.0.2":      {IP: "10.8.0.2", MAC: "00:11:22:33:44:55", Iface: "utun0"},    // other subnet
	}

	got := mergeProbeAndARP(ping, arp, "192.168.0.0/24", "en0", now)
	if len(got) != 2 {
		t.Fatalf("expected 2 in-subnet devices, got %d: %+v", len(got), got)
	}
	byIP := map[string]RawDevice{}
	for _, d := range got {
		byIP[d.IP] = d
	}
	router := byIP["192.168.0.1"]
	if router.MAC != "AA:BB:CC:DD:EE:01" || router.Hostname != "router.local" {
		t.Fatalf("probe enrichment: %+v", router)
	}
	silent := byIP["192.168.0.132"]
	if silent.MAC != "28:CD:C1:01:43:34" || !silent.IsOnline {
		t.Fatalf("ARP-complete host missing: %+v", silent)
	}
	if _, ok := byIP["10.8.0.2"]; ok {
		t.Fatal("out-of-subnet ARP row should be excluded")
	}
}

func TestMergeProbeAndARPSkipsOtherIface(t *testing.T) {
	arp := map[string]RawDevice{
		"192.168.0.50": {IP: "192.168.0.50", MAC: "AA:BB:CC:DD:EE:50", Iface: "en1"},
	}
	got := mergeProbeAndARP(nil, arp, "192.168.0.0/24", "en0", time.Now())
	if len(got) != 0 {
		t.Fatalf("expected no devices on other iface, got %+v", got)
	}
}

func TestParseARPLineWithHostname(t *testing.T) {
	tests := []struct {
		line         string
		wantIP       string
		wantMAC      string
		wantHostname string
		wantMatch    bool
	}{
		{
			line:         "amys-mbp.local (192.168.0.142) at 8c:85:90:24:10:b7 on en0 ifscope [ethernet]",
			wantIP:       "192.168.0.142",
			wantMAC:      "8C:85:90:24:10:B7",
			wantHostname: "amys-mbp.local",
			wantMatch:    true,
		},
		{
			line:         "? (192.168.0.10) at 0:1c:42:11:22:33 on en0 ifscope [ethernet]",
			wantIP:       "192.168.0.10",
			wantMAC:      "00:1C:42:11:22:33",
			wantHostname: "",
			wantMatch:    true,
		},
		{
			line:      "garbage",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		matches := arpLineRe.FindStringSubmatch(tt.line)
		if tt.wantMatch && len(matches) < 5 {
			t.Fatalf("expected match for %q", tt.line)
		}
		if !tt.wantMatch {
			continue
		}
		name, ip, mac := matches[1], matches[2], formatMAC(matches[3])
		host := ""
		if name != "?" {
			host = name
		}
		if ip != tt.wantIP || mac != tt.wantMAC || host != tt.wantHostname {
			t.Fatalf("line %q => ip=%q mac=%q host=%q", tt.line, ip, mac, host)
		}
	}
}

func TestMergeProbeAndARPIncludesPingWithoutARP(t *testing.T) {
	got := mergeProbeAndARP(map[string]float64{"10.0.0.5": 3.0}, map[string]RawDevice{}, "10.0.0.0/24", "en0", time.Now())
	if len(got) != 1 || got[0].MAC != "" || !got[0].IsOnline {
		t.Fatalf("unexpected result: %+v", got)
	}
}
