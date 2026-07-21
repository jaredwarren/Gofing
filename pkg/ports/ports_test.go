package ports

import (
	"testing"
	"time"
)

func TestDedupSort(t *testing.T) {
	in := []ServicePort{
		{443, "HTTPS"},
		{80, "HTTP"},
		{80, "HTTP"},
		{22, "SSH"},
	}
	got := DedupSort(in)
	if len(got) != 3 {
		t.Fatalf("len=%d want 3: %+v", len(got), got)
	}
	if got[0].Port != 22 || got[1].Port != 80 || got[2].Port != 443 {
		t.Fatalf("order: %+v", got)
	}
}

func TestScanPortsRangeCap(t *testing.T) {
	// Request a huge range; implementation must cap at MaxDeepPorts probes.
	got := ScanPortsRange("127.0.0.1", 1, 5000, 128, 5*time.Millisecond)
	if len(got) > MaxDeepPorts {
		t.Fatalf("got %d open ports, over cap", len(got))
	}
}

func TestPortNameKnown(t *testing.T) {
	if PortName(22) != "SSH" {
		t.Fatalf("PortName(22)=%q", PortName(22))
	}
	if PortName(59999) != "TCP 59999" {
		t.Fatalf("PortName(59999)=%q", PortName(59999))
	}
}

func TestCommonPortsExpanded(t *testing.T) {
	want := map[int]bool{21: true, 23: true, 548: true, 8291: true, 8443: true, 9100: true}
	for _, p := range CommonPorts {
		delete(want, p.Port)
	}
	if len(want) > 0 {
		t.Fatalf("missing common ports: %v", want)
	}
}
