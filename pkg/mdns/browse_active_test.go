package mdns

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeDNSName(t *testing.T) {
	got, err := encodeDNSName("_companion-link._tcp.local")
	if err != nil {
		t.Fatalf("encodeDNSName: %v", err)
	}
	want := []byte{
		15, '_', 'c', 'o', 'm', 'p', 'a', 'n', 'i', 'o', 'n', '-', 'l', 'i', 'n', 'k',
		4, '_', 't', 'c', 'p',
		5, 'l', 'o', 'c', 'a', 'l',
		0,
	}
	if string(got) != string(want) {
		t.Fatalf("encoding mismatch\n got %v\nwant %v", got, want)
	}

	// A trailing dot is the same name.
	dotted, err := encodeDNSName("_companion-link._tcp.local.")
	if err != nil {
		t.Fatalf("trailing dot: %v", err)
	}
	if string(dotted) != string(want) {
		t.Error("a trailing dot should encode identically")
	}
}

func TestEncodeDNSNameRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "   ", ".", "a..b", strings.Repeat("x", 64) + ".local"} {
		if _, err := encodeDNSName(bad); err == nil {
			t.Errorf("encodeDNSName(%q) should have failed", bad)
		}
	}
}

func TestBuildServiceQueryHeader(t *testing.T) {
	svcs := []string{"_airplay._tcp.local", "_hap._tcp.local"}
	msg, err := buildServiceQuery(svcs)
	if err != nil {
		t.Fatalf("buildServiceQuery: %v", err)
	}
	if len(msg) < 12 {
		t.Fatal("packet shorter than a DNS header")
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != 0 {
		t.Errorf("ID = %d, want 0", id)
	}
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags != 0 {
		t.Errorf("flags = %#04x, want 0 (standard query, multicast response)", flags)
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); int(qd) != len(svcs) {
		t.Errorf("QDCOUNT = %d, want %d", qd, len(svcs))
	}
	for i, name := range []string{"ANCOUNT", "NSCOUNT", "ARCOUNT"} {
		off := 6 + i*2
		if v := binary.BigEndian.Uint16(msg[off : off+2]); v != 0 {
			t.Errorf("%s = %d, want 0", name, v)
		}
	}
}

// TestBuildServiceQueryIsParseable is the important one: the packet we transmit
// must be well-formed by the same reader that consumes real mDNS traffic.
// A malformed question section would be dropped silently by every responder.
func TestBuildServiceQueryIsParseable(t *testing.T) {
	msg, err := buildServiceQuery(DefaultBrowseServices)
	if err != nil {
		t.Fatalf("buildServiceQuery: %v", err)
	}
	// A query carries questions and no records; parsing must walk the whole
	// question section without erroring and find nothing to learn.
	rrs, err := parseResourceRecords(msg)
	if err != nil {
		t.Fatalf("our own query does not parse: %v", err)
	}
	if len(rrs) != 0 {
		t.Fatalf("a query should contain no resource records, got %d", len(rrs))
	}
}

func TestBuildServiceQuerySkipsBadNamesButKeepsGood(t *testing.T) {
	msg, err := buildServiceQuery([]string{"a..b", "_hap._tcp.local"})
	if err != nil {
		t.Fatalf("buildServiceQuery: %v", err)
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd != 1 {
		t.Fatalf("QDCOUNT = %d, want 1 (bad name skipped, good name kept)", qd)
	}
}

func TestBuildServiceQueryNoUsableServices(t *testing.T) {
	if _, err := buildServiceQuery([]string{"", "..."}); err == nil {
		t.Fatal("expected an error when nothing is encodable")
	}
}

func TestBrowseValidatesInput(t *testing.T) {
	var nilResolver *Resolver
	if err := nilResolver.Browse(nil, "en0", nil); err == nil {
		t.Error("nil resolver should error")
	}
	r := New()
	if err := r.Browse(nil, "", nil); err == nil {
		t.Error("empty interface should error")
	}
}

func TestDefaultBrowseServicesAreWellFormed(t *testing.T) {
	if len(DefaultBrowseServices) == 0 {
		t.Fatal("no default services")
	}
	seen := map[string]bool{}
	for _, svc := range DefaultBrowseServices {
		if seen[svc] {
			t.Errorf("duplicate service type %q", svc)
		}
		seen[svc] = true
		if !strings.HasPrefix(svc, "_") {
			t.Errorf("%q should start with an underscore", svc)
		}
		if !strings.HasSuffix(svc, ".local") {
			t.Errorf("%q should be scoped to .local", svc)
		}
		if _, err := encodeDNSName(svc); err != nil {
			t.Errorf("%q does not encode: %v", svc, err)
		}
	}
}
