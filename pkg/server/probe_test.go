package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/scanner"
)

func TestHandleProbeDevice(t *testing.T) {
	eng := engine.New(nil)
	eng.SetActiveNetwork(&network.Info{
		SSID: "TestNet", SubnetCIDR: "192.168.1.0/24",
		GatewayIP: "192.168.1.1", InterfaceName: "en0",
	})
	id := eng.UpsertForTest(
		scanner.RawDevice{IP: "192.168.1.50", MAC: "00:11:22:33:44:55"},
		mdns.DeviceDetails{Hostname: "test-device"}, "Acme", time.Now(),
	)

	srv := New(eng, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})
	handler := srv.Handler()

	// Test GET not allowed
	reqGet := httptest.NewRequest(http.MethodGet, "/api/devices/"+id+"/probe", nil)
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rrGet.Code)
	}

	// Test POST probe succeeds
	reqPost := httptest.NewRequest(http.MethodPost, "/api/devices/"+id+"/probe", nil)
	rrPost := httptest.NewRecorder()
	handler.ServeHTTP(rrPost, reqPost)
	if rrPost.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST, got %d: %s", rrPost.Code, rrPost.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rrPost.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("expected status 'success', got %v", resp["status"])
	}
	if resp["device"] == nil {
		t.Errorf("expected device in response")
	}
}
