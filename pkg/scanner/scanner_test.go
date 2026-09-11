package scanner

import (
	"context"
	"errors"
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

// TestMergeProbeAndARPDropsPingWithoutARP pins a deliberate behavior change.
//
// This previously returned the address as a MAC-less host. Under the sweep's
// 48-way concurrency macOS reports sub-millisecond TCP connects for addresses
// that are unreachable to any serial probe and `(incomplete)` in the ARP
// table, so that rule invented a phantom device per false positive — 44 of
// them accumulated in one real inventory inside two days — and briefly marked
// genuinely absent devices online. A host on a directly-connected subnet
// cannot pass IP traffic without a resolved ARP entry, so the entry is the
// evidence and the probe reply alone is not.
func TestMergeProbeAndARPDropsPingWithoutARP(t *testing.T) {
	got := mergeProbeAndARP(map[string]float64{"10.0.0.5": 3.0}, map[string]RawDevice{}, "10.0.0.0/24", "en0", time.Now())
	if len(got) != 0 {
		t.Fatalf("probe reply with no ARP entry must be discarded, got %+v", got)
	}
}

func TestMergeProbeAndARPKeepsPingWithARP(t *testing.T) {
	arp := map[string]RawDevice{
		"10.0.0.5": {IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:05", Iface: "en0", Hostname: "pi"},
	}
	got := mergeProbeAndARP(map[string]float64{"10.0.0.5": 3.0}, arp, "10.0.0.0/24", "en0", time.Now())
	if len(got) != 1 {
		t.Fatalf("expected the ARP-backed host, got %+v", got)
	}
	if got[0].MAC != "AA:BB:CC:DD:EE:05" {
		t.Errorf("MAC = %q, want it carried over from ARP", got[0].MAC)
	}
	if got[0].LatencyMs != 3.0 {
		t.Errorf("LatencyMs = %v, want the measured 3.0 preserved", got[0].LatencyMs)
	}
	if got[0].Hostname != "pi" {
		t.Errorf("Hostname = %q, want it carried over from ARP", got[0].Hostname)
	}
	if !got[0].IsOnline {
		t.Error("IsOnline should be true")
	}
}

func TestMergeProbeAndARPRejectsOtherInterface(t *testing.T) {
	arp := map[string]RawDevice{
		"10.0.0.5": {IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:05", Iface: "en1"},
	}
	got := mergeProbeAndARP(map[string]float64{"10.0.0.5": 3.0}, arp, "10.0.0.0/24", "en0", time.Now())
	if len(got) != 0 {
		t.Fatalf("ARP evidence from another interface must not count, got %+v", got)
	}
}

func TestFilterSkippedIPs(t *testing.T) {
	ips := []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}
	got := filterSkippedIPs(ips, map[string]float64{"192.168.0.2": 1.5})
	if len(got) != 2 || got[0] != "192.168.0.1" || got[1] != "192.168.0.3" {
		t.Fatalf("got %v", got)
	}
	if same := filterSkippedIPs(ips, nil); len(same) != 3 {
		t.Fatalf("nil skip should keep all, got %v", same)
	}
}

func TestApplySkipHits(t *testing.T) {
	ping := map[string]float64{"192.168.0.1": 2.0}
	applySkipHits(ping, map[string]float64{"192.168.0.5": 1.1, "192.168.0.1": 9.9})
	if ping["192.168.0.5"] != 1.1 {
		t.Fatalf("missing skip hit: %v", ping)
	}
	if ping["192.168.0.1"] != 2.0 {
		t.Fatalf("existing ping result must not be overwritten: %v", ping)
	}
}

func TestProbeIPQuickCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := ProbeIPQuick(ctx, "192.0.2.1"); ok {
		t.Fatal("cancelled probe must not report a hit")
	}
}

func TestARPTableCachedReusesWithinTTL(t *testing.T) {
	s := New()
	calls := 0
	s.arpExecFn = func(ctx context.Context, numeric bool) ([]RawDevice, error) {
		calls++
		return []RawDevice{{IP: "192.168.0.5", MAC: "AA:BB:CC:DD:EE:05"}}, nil
	}

	if _, err := s.ARPTableNumeric(context.Background(), time.Minute); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := s.ARPTableNumeric(context.Background(), time.Minute); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if calls != 1 {
		t.Fatalf("exec ran %d times within the TTL; want 1", calls)
	}

	// maxAge <= 0 must always re-exec.
	if _, err := s.ARPTableNumeric(context.Background(), 0); err != nil {
		t.Fatalf("forced call: %v", err)
	}
	if calls != 2 {
		t.Fatalf("exec ran %d times; want 2 after a forced refresh", calls)
	}
}

func TestARPTableCachedReturnsCopy(t *testing.T) {
	s := New()
	s.arpExecFn = func(ctx context.Context, numeric bool) ([]RawDevice, error) {
		return []RawDevice{{IP: "192.168.0.5", MAC: "AA:BB:CC:DD:EE:05"}}, nil
	}
	first, err := s.ARPTableNumeric(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	first[0].IP = "mutated"

	second, err := s.ARPTableNumeric(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second[0].IP != "192.168.0.5" {
		t.Fatalf("caller mutated the cache: got %q", second[0].IP)
	}
}

func TestARPTableCachedPropagatesError(t *testing.T) {
	s := New()
	s.arpExecFn = func(ctx context.Context, numeric bool) ([]RawDevice, error) {
		return nil, errors.New("arp unavailable")
	}
	if _, err := s.ARPTableNumeric(context.Background(), time.Minute); err == nil {
		t.Fatal("expected the exec error to propagate")
	}
}

func TestARPTableNumericAndNamedCacheSeparately(t *testing.T) {
	s := New()
	var numericCalls, namedCalls int
	s.arpExecFn = func(ctx context.Context, numeric bool) ([]RawDevice, error) {
		if numeric {
			numericCalls++
		} else {
			namedCalls++
		}
		return []RawDevice{{IP: "192.168.0.5", MAC: "AA:BB:CC:DD:EE:05"}}, nil
	}

	// The two forms cost three orders of magnitude apart, so a cheap numeric
	// read must never be served from the expensive name-resolving cache, or
	// vice versa.
	if _, err := s.ARPTableNumeric(context.Background(), time.Minute); err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if _, err := s.ARPTableCached(context.Background(), time.Minute); err != nil {
		t.Fatalf("named: %v", err)
	}
	if numericCalls != 1 || namedCalls != 1 {
		t.Fatalf("numeric=%d named=%d; want one exec of each", numericCalls, namedCalls)
	}

	// Each form then serves from its own cache.
	_, _ = s.ARPTableNumeric(context.Background(), time.Minute)
	_, _ = s.ARPTableCached(context.Background(), time.Minute)
	if numericCalls != 1 || namedCalls != 1 {
		t.Fatalf("numeric=%d named=%d; want both still cached", numericCalls, namedCalls)
	}
}

func TestParseARPReachabilityInformation(t *testing.T) {
	// Sample output from `arp -n -l -a` containing:
	// - router (reachable)
	// - iPad (reachable, countdown timer)
	// - disconnected Watch (incomplete)
	// - disconnected GamingLaptop (expired exp_o & exp_i, prbs=36)
	// - failed probe host (exp_i=expired, prbs=12)
	// - multicast entry (should be skipped)
	sample := `
Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs
192.168.0.1             54:af:97:14:cf:7c 2m38s     2m30s          en0    1
192.168.0.4             (incomplete)      1m16s     expired        en0    2   35
192.168.0.156           ae:35:5:49:5a:c   1m3s      41s            en0    1
169.254.33.142          f4:28:9d:d0:33:d7 expired   expired        en0    2   36
192.168.0.77            aa:bb:cc:dd:ee:77 1m20s     expired        en0    1   12
224.0.0.251             1:0:5e:0:0:fb     (none)    (none)         en0
`
	devs := parseARPTableOutput(sample, time.Now())
	if len(devs) != 2 {
		t.Fatalf("expected 2 reachable devices, got %d: %+v", len(devs), devs)
	}
	byIP := make(map[string]RawDevice)
	for _, d := range devs {
		byIP[d.IP] = d
	}
	if d, ok := byIP["192.168.0.1"]; !ok || d.MAC != "54:AF:97:14:CF:7C" {
		t.Errorf("router missing or incorrect: %+v", d)
	}
	if d, ok := byIP["192.168.0.156"]; !ok || d.MAC != "AE:35:05:49:5A:0C" {
		t.Errorf("iPad missing or incorrect: %+v", d)
	}
	if _, ok := byIP["192.168.0.4"]; ok {
		t.Errorf("incomplete device should be excluded")
	}
	if _, ok := byIP["169.254.33.142"]; ok {
		t.Errorf("double-expired device should be excluded")
	}
	if _, ok := byIP["192.168.0.77"]; ok {
		t.Errorf("device with failed probes should be excluded")
	}
	if _, ok := byIP["224.0.0.251"]; ok {
		t.Errorf("multicast entry should be excluded")
	}
}

func TestIsTCPRefused(t *testing.T) {
	if isTCPRefused(nil) {
		t.Error("nil error should not be refused")
	}
	if !isTCPRefused(errors.New("dial tcp 192.168.0.1:80: connect: connection refused")) {
		t.Error("connection refused string should be detected")
	}
	if isTCPRefused(errors.New("i/o timeout")) {
		t.Error("timeout should not be detected as refused")
	}
}
