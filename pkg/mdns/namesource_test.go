package mdns

import "testing"

func TestNameSourceRank(t *testing.T) {
	if NameSourceRank(NameSourceARP) <= NameSourceRank(NameSourceDNS) {
		t.Fatal("ARP should outrank DNS")
	}
	if NameSourceRank(NameSourceDNS) <= NameSourceRank(NameSourceHTTP) {
		t.Fatal("DNS should outrank HTTP")
	}
	if NameSourceRank(NameSourceNone) != 0 {
		t.Fatal("none should be 0")
	}
}

func TestPreferHostnameUpgradeOnly(t *testing.T) {
	// Empty → accept ARP
	name, src := PreferHostname("", NameSourceNone, "amys-mbp", NameSourceARP)
	if name != "amys-mbp" || src != NameSourceARP {
		t.Fatalf("got %q/%q", name, src)
	}

	// ARP stored: lower HTTP must not overwrite
	name, src = PreferHostname("amys-mbp", NameSourceARP, "Router Admin", NameSourceHTTP)
	if name != "amys-mbp" || src != NameSourceARP {
		t.Fatalf("HTTP demotion: got %q/%q", name, src)
	}

	// DNS stored: higher ARP upgrades
	name, src = PreferHostname("amys-mbp.lan", NameSourceDNS, "AMYS-MBP", NameSourceARP)
	if name != "AMYS-MBP" || src != NameSourceARP {
		t.Fatalf("ARP upgrade: got %q/%q", name, src)
	}

	// Equal rank: keep existing (no flap)
	name, src = PreferHostname("amys-mbp", NameSourceDNS, "AMYS-MBP", NameSourceDNS)
	if name != "amys-mbp" || src != NameSourceDNS {
		t.Fatalf("equal rank: got %q/%q", name, src)
	}

	// Junk existing cleared, then candidate wins
	name, src = PreferHostname("Record", NameSourceHTTP, "amys-mbp", NameSourceARP)
	if name != "amys-mbp" || src != NameSourceARP {
		t.Fatalf("junk clear: got %q/%q", name, src)
	}

	// Garbage candidate ignored
	name, src = PreferHostname("amys-mbp", NameSourceARP, "���$�", NameSourceDNS)
	if name != "amys-mbp" || src != NameSourceARP {
		t.Fatalf("garbage candidate: got %q/%q", name, src)
	}
}
