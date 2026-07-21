package mdns

import "testing"

func TestParseDNSSDLookupOutputTXT(t *testing.T) {
	out := `
Lookup Amy's MacBook._companion-link._tcp.local
 DATE: ---Tue 21 Jul 2026---
16:00:00.000  Amy's MacBook._companion-link._tcp.local. can be reached at AMYS-MBP.local.:7000 (interface 14)
 model=MacBookPro18,1 osxvers=22
`
	host, txt := parseDNSSDLookupOutput(out)
	if host != "AMYS-MBP" {
		t.Fatalf("host=%q", host)
	}
	if txt["model"] != "MacBookPro18,1" {
		t.Fatalf("txt=%v", txt)
	}
	hints := hintsFromTXT("_companion-link._tcp", txt)
	if hints.Model != "MacBook Pro" {
		t.Fatalf("model=%q", hints.Model)
	}
	if hints.DeviceType != "Computer" {
		t.Fatalf("type=%q", hints.DeviceType)
	}
	foundAirPlay := false
	for _, s := range hints.Services {
		if s == "AirPlay" {
			foundAirPlay = true
		}
	}
	if !foundAirPlay {
		t.Fatalf("services=%v", hints.Services)
	}
}

func TestHintsFromPrinterTXT(t *testing.T) {
	hints := hintsFromTXT("_ipp._tcp", map[string]string{"ty": "HP LaserJet"})
	if hints.DeviceType != "Printer" || hints.Model != "HP LaserJet" {
		t.Fatalf("%+v", hints)
	}
}

func TestHumanizeModel(t *testing.T) {
	if got := humanizeModel("MacBookAir10,1"); got != "MacBook Air" {
		t.Fatalf("got %q", got)
	}
}
