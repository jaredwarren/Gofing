package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

// scopedIDEngine seeds one device whose stable ID contains a slash, which is
// what every network-scoped device looks like in practice.
func scopedIDEngine(t *testing.T) (string, http.Handler) {
	t.Helper()
	eng := engine.New(nil)
	eng.SetActiveNetwork(&network.Info{
		SSID: "Wired / Ethernet", SubnetCIDR: "192.168.0.0/24",
		GatewayIP: "192.168.0.1", InterfaceName: "en0",
	})
	id := eng.UpsertForTest(
		scanner.RawDevice{IP: "192.168.0.99", MAC: "64:CD:C2:94:A5:73"},
		mdns.DeviceDetails{Hostname: "printer"}, "Acme", time.Now())

	srv := New(eng, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})
	return id, srv.Handler()
}

// TestDeviceSubpathHandlesScopedIDs covers a routing bug: the dispatcher used
// to split the path and take the first segment as the device ID, so every
// scoped ID ("ssid:Home/AA:BB:...") 404'd on all of its subroutes.
func TestDeviceSubpathHandlesScopedIDs(t *testing.T) {
	id, h := scopedIDEngine(t)
	if !strings.Contains(id, "/") {
		t.Fatalf("test needs a slash-containing id, got %q", id)
	}
	escaped := url.PathEscape(id)

	tests := []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, "/api/devices/" + escaped, http.StatusOK},
		{http.MethodGet, "/api/devices/" + escaped + "/history", http.StatusOK},
		{http.MethodPost, "/api/devices/" + escaped + "/enrich", http.StatusOK},
		{http.MethodPost, "/api/devices/" + escaped + "/portscan", http.StatusOK},
		// An unknown trailing segment is not an action, so the whole path reads
		// as an ID, which does not exist.
		{http.MethodGet, "/api/devices/" + escaped + "/bogus", http.StatusNotFound},
		{http.MethodPost, "/api/devices/nope/enrich", http.StatusNotFound},
		// Wrong method on a real action.
		{http.MethodGet, "/api/devices/" + escaped + "/enrich", http.StatusMethodNotAllowed},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s %s = %d, want %d (body %q)",
				tc.method, tc.path, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}
}

func TestEnrichDedupes(t *testing.T) {
	id, h := scopedIDEngine(t)
	path := "/api/devices/" + url.PathEscape(id) + "/enrich"

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodPost, path, nil))
	if got := first.Body.String(); !strings.Contains(got, "enrich_started") {
		t.Fatalf("first request body = %q, want enrich_started", got)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodPost, path, nil))
	if got := second.Body.String(); !strings.Contains(got, "already_running") {
		t.Fatalf("second request body = %q, want already_running", got)
	}
}

func TestDevicesRootReportsTierStatus(t *testing.T) {
	_, h := scopedIDEngine(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	// The web UI reads only .devices and .is_scanning, so the added key must be
	// present without disturbing those.
	for _, want := range []string{`"devices"`, `"is_scanning"`, `"tiers"`,
		`"enrich_pending"`, `"discovery_interval_sec"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %s: %s", want, body)
		}
	}
}
