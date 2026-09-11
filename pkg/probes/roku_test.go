package probes

import "testing"

// Captured verbatim from a Roku Streaming Stick 4K on the development LAN.
const rokuSample = `<device-info>
  <udn>1b6ea1f0-6c1a-51d6-9b34-9f1e2a1c0000</udn>
  <serial-number>X02500FR74WP</serial-number>
  <device-id>S01234567890</device-id>
  <vendor-name>Roku</vendor-name>
  <model-name>Streaming Stick 4K</model-name>
  <model-number>3820R2</model-number>
  <software-version>13.0.0</software-version>
  <friendly-device-name>Streaming Stick 4K</friendly-device-name>
  <user-device-name>Living room 2</user-device-name>
</device-info>`

func TestParseRokuDeviceInfo(t *testing.T) {
	got, err := parseRokuDeviceInfo([]byte(rokuSample))
	if err != nil {
		t.Fatalf("parseRokuDeviceInfo: %v", err)
	}
	// The owner-assigned name is the point; the friendly name is just the model.
	if got.Name != "Living room 2" {
		t.Errorf("Name = %q, want the user-assigned name", got.Name)
	}
	if got.ModelName != "Streaming Stick 4K" {
		t.Errorf("ModelName = %q", got.ModelName)
	}
	if got.ModelNumber != "3820R2" {
		t.Errorf("ModelNumber = %q", got.ModelNumber)
	}
	if got.VendorName != "Roku" {
		t.Errorf("VendorName = %q", got.VendorName)
	}
	if got.SerialNumber != "X02500FR74WP" {
		t.Errorf("SerialNumber = %q", got.SerialNumber)
	}
}

func TestParseRokuFallsBackToFriendlyName(t *testing.T) {
	got, err := parseRokuDeviceInfo([]byte(
		`<device-info><vendor-name>Roku</vendor-name><friendly-device-name>Bedroom TV</friendly-device-name></device-info>`))
	if err != nil {
		t.Fatalf("parseRokuDeviceInfo: %v", err)
	}
	if got.Name != "Bedroom TV" {
		t.Errorf("Name = %q, want the friendly name when no user name is set", got.Name)
	}
}

func TestParseRokuRejectsNonRoku(t *testing.T) {
	for _, bad := range []string{
		``,
		`not xml at all`,
		`<device-info></device-info>`, // well-formed but empty
		`<root><device><friendlyName>x</friendlyName></device></root>`, // a UPnP doc
	} {
		if _, err := parseRokuDeviceInfo([]byte(bad)); err == nil {
			t.Errorf("should have rejected %q", bad)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("got %q, want x", got)
	}
	if got := firstNonEmpty("", "   "); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
