package probes

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestParseUPnPXML(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Sonos Era 100 - Living Room</friendlyName>
    <manufacturer>Sonos, Inc.</manufacturer>
    <modelName>Era 100</modelName>
    <modelNumber>S39</modelNumber>
    <modelDescription>Smart Speaker</modelDescription>
    <presentationURL>http://192.168.0.45:1400/index.html</presentationURL>
  </device>
</root>`

	info, err := parseUPnPXML([]byte(xmlData))
	if err != nil {
		t.Fatalf("parseUPnPXML error: %v", err)
	}
	if info.FriendlyName != "Sonos Era 100 - Living Room" {
		t.Errorf("expected friendly name 'Sonos Era 100 - Living Room', got %q", info.FriendlyName)
	}
	if info.Manufacturer != "Sonos, Inc." {
		t.Errorf("expected manufacturer 'Sonos, Inc.', got %q", info.Manufacturer)
	}
	if info.ModelName != "Era 100" {
		t.Errorf("expected model name 'Era 100', got %q", info.ModelName)
	}
	if info.ModelNumber != "S39" {
		t.Errorf("expected model number 'S39', got %q", info.ModelNumber)
	}
	if info.PresentationURL != "http://192.168.0.45:1400/index.html" {
		t.Errorf("expected presentation URL 'http://192.168.0.45:1400/index.html', got %q", info.PresentationURL)
	}
}

func TestParseNetBIOSResponse(t *testing.T) {
	// Construct a synthetic RFC 1002 Node Status response
	resp := make([]byte, 100)
	// Header
	resp[0] = 0x82
	resp[1] = 0x28 // Transaction ID
	resp[2] = 0x84 // Flags: response
	resp[3] = 0x00
	resp[6] = 0x00
	resp[7] = 0x01 // Answer RRs: 1

	// Question echo or dummy at offset 12..40
	// Answer section: Name pointer (2 bytes), Type NBSTAT (0x0021), Class IN (0x0001), TTL (4 bytes), RDLENGTH (2 bytes)
	offset := 40
	resp[offset] = 0x00
	resp[offset+1] = 0x21 // Type NBSTAT
	resp[offset+2] = 0x00
	resp[offset+3] = 0x01 // Class IN
	// TTL
	resp[offset+4] = 0x00
	resp[offset+5] = 0x00
	resp[offset+6] = 0x00
	resp[offset+7] = 0x00
	// RDLENGTH
	resp[offset+8] = 0x00
	resp[offset+9] = 0x2B // 43 bytes of RDATA (1 num_names + 2*18 name records + 6 unit_id)

	rdataOffset := offset + 10
	resp[rdataOffset] = 0x02 // 2 names

	// Record 1: WORKGROUP (group name, suffix 0x00)
	rec1 := rdataOffset + 1
	copy(resp[rec1:rec1+15], []byte("WORKGROUP      "))
	resp[rec1+15] = 0x00 // Suffix
	resp[rec1+16] = 0x84 // Group flag bit set (0x8000)
	resp[rec1+17] = 0x00

	// Record 2: MY-PC (unique name, suffix 0x00)
	rec2 := rec1 + 18
	copy(resp[rec2:rec2+15], []byte("MY-PC          "))
	resp[rec2+15] = 0x00 // Suffix
	resp[rec2+16] = 0x04 // Unique (0x8000 NOT set)
	resp[rec2+17] = 0x00

	// Unit ID (MAC: 00:11:22:33:44:55)
	macOffset := rec2 + 18
	copy(resp[macOffset:macOffset+6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	info, err := parseNetBIOSResponse(resp[:macOffset+6])
	if err != nil {
		t.Fatalf("parseNetBIOSResponse error: %v", err)
	}

	if info.ComputerName != "MY-PC" {
		t.Errorf("expected computer name 'MY-PC', got %q", info.ComputerName)
	}
	if info.Workgroup != "WORKGROUP" {
		t.Errorf("expected workgroup 'WORKGROUP', got %q", info.Workgroup)
	}
	if info.MAC != "00:11:22:33:44:55" {
		t.Errorf("expected MAC '00:11:22:33:44:55', got %q", info.MAC)
	}
}

func TestInspectTLSCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "synology.local",
		},
		DNSNames: []string{"synology.local", "diskstation.lan"},
		Issuer: pkix.Name{
			Organization: []string{"Synology Inc."},
		},
	}

	info := inspectTLSCert(cert, 443)
	if info == nil {
		t.Fatalf("expected non-nil TLSInfo")
	}
	if info.SubjectCN != "synology.local" {
		t.Errorf("expected SubjectCN 'synology.local', got %q", info.SubjectCN)
	}
	if len(info.SANs) != 2 || info.SANs[1] != "diskstation.lan" {
		t.Errorf("expected SANs containing 'diskstation.lan', got %v", info.SANs)
	}
	if info.IssuerOrg != "Synology Inc." {
		t.Errorf("expected IssuerOrg 'Synology Inc.', got %q", info.IssuerOrg)
	}
}

func TestProbeDeviceEmptyIP(t *testing.T) {
	res := ProbeDevice(context.Background(), "", nil)
	if res.IP != "" || res.UPnP != nil || res.NetBIOS != nil || res.TLS != nil {
		t.Errorf("expected empty result for empty IP, got %+v", res)
	}
}
