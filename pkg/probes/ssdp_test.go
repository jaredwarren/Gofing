package probes

import (
	"strings"
	"testing"
)

// Shaped like the reply the development LAN's Archer AX73 actually sends.
const ssdpSample = "HTTP/1.1 200 OK\r\n" +
	"CACHE-CONTROL: max-age=120\r\n" +
	"ST: upnp:rootdevice\r\n" +
	"USN: uuid:ba33007f-af74-4413-ae4b-7cec96ebddc6::upnp:rootdevice\r\n" +
	"EXT:\r\n" +
	"SERVER: TP-LINK/1.0 UPnP/1.0 MiniUPnPd/2.3\r\n" +
	"LOCATION: http://192.168.0.1:1900/lohda/rootDesc.xml\r\n" +
	"\r\n"

func TestParseSSDPResponse(t *testing.T) {
	got, err := parseSSDPResponse([]byte(ssdpSample))
	if err != nil {
		t.Fatalf("parseSSDPResponse: %v", err)
	}
	if got.Location != "http://192.168.0.1:1900/lohda/rootDesc.xml" {
		t.Errorf("Location = %q", got.Location)
	}
	if got.Server != "TP-LINK/1.0 UPnP/1.0 MiniUPnPd/2.3" {
		t.Errorf("Server = %q", got.Server)
	}
	if got.ST != "upnp:rootdevice" {
		t.Errorf("ST = %q", got.ST)
	}
	if got.USN == "" {
		t.Error("USN should be captured")
	}
}

func TestParseSSDPResponseRejectsJunk(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"not ssdp":         "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"non-200":          "HTTP/1.1 404 Not Found\r\n\r\n",
		"200 with nothing": "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\r\n",
	}
	for name, body := range cases {
		if _, err := parseSSDPResponse([]byte(body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSSDPMSearchIsWellFormed(t *testing.T) {
	// Responders are strict about this: MAN must be quoted and the packet must
	// end in a blank line, or the search is silently ignored.
	for _, want := range []string{
		"M-SEARCH * HTTP/1.1\r\n",
		"HOST: 239.255.255.250:1900\r\n",
		"MAN: \"ssdp:discover\"\r\n",
		"ST: upnp:rootdevice\r\n",
	} {
		if !strings.Contains(ssdpMSearch, want) {
			t.Errorf("M-SEARCH missing %q", want)
		}
	}
	if len(ssdpMSearch) < 4 || ssdpMSearch[len(ssdpMSearch)-4:] != "\r\n\r\n" {
		t.Error("M-SEARCH must terminate with a blank line")
	}
}
