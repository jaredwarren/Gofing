package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/version"
)

func TestHandleVersion(t *testing.T) {
	origV := version.Version
	origT := version.BuildTime
	defer func() {
		version.Version = origV
		version.BuildTime = origT
	}()

	version.Version = "1.0.42"
	version.BuildTime = "2026-09-10 12:00:00"

	eng := engine.New(nil)
	srv := New(eng, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp["version"] != "1.0.42" {
		t.Errorf("expected version 1.0.42, got %s", resp["version"])
	}
	if resp["build_time"] != "2026-09-10 12:00:00" {
		t.Errorf("expected build_time 2026-09-10 12:00:00, got %s", resp["build_time"])
	}

	// Test non-GET method rejected
	postReq := httptest.NewRequest(http.MethodPost, "/api/version", nil)
	postRr := httptest.NewRecorder()
	handler.ServeHTTP(postRr, postReq)
	if postRr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for POST, got %d", postRr.Code)
	}
}
