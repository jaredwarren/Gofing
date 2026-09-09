package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/jaredwarren/Gofing/pkg/dhcp"
	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/notify"
)

// Server encapsulates the HTTP API, SSE streaming, and embedded frontend delivery.
type Server struct {
	devEngine  *engine.Engine
	staticFS   fs.FS
	sseClients map[chan string]bool
	sseMu      sync.RWMutex
}

// New returns a new Server instance.
func New(devEngine *engine.Engine, staticFS fs.FS) *Server {
	srv := &Server{
		devEngine:  devEngine,
		staticFS:   staticFS,
		sseClients: make(map[chan string]bool),
	}

	devEngine.RegisterEventListener(func(eventType string, data interface{}) {
		srv.broadcastSSE(eventType, data)
	})

	return srv
}

// Handler returns the http.Handler for all endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/network", s.handleNetworkInfo)
	mux.HandleFunc("/api/devices", s.handleDevicesRoot)
	mux.HandleFunc("/api/devices/", s.handleDeviceSubpath)
	mux.HandleFunc("/api/scan", s.handleTriggerScan)
	mux.HandleFunc("/api/dhcp/import", s.handleDHCPImport)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/events/history", s.handleEventsHistory)
	mux.HandleFunc("/api/events", s.handleSSE)
	mux.HandleFunc("/api/notify/test", s.handleTestNotification)

	fileServer := http.FileServer(http.FS(s.staticFS))
	mux.Handle("/", fileServer)

	return mux
}

func (s *Server) handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	info, err := network.GetActiveNetworkInfo()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get network info: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, info)
}

func (s *Server) handleDevicesRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices := s.devEngine.GetDevices()
	writeJSON(w, map[string]interface{}{
		"devices":     devices,
		"is_scanning": s.devEngine.IsScanning(),
		"tiers":       s.devEngine.TierStatus(),
	})
}

// deviceActions are the recognized /api/devices/{id}/<action> suffixes.
var deviceActions = map[string]bool{
	"history":      true,
	"rdns":         true,
	"resolve-name": true,
	"portscan":     true,
	"enrich":       true,
}

// handleDeviceSubpath serves /api/devices/{id} and /api/devices/{id}/<action>.
func (s *Server) handleDeviceSubpath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	// A scoped device ID contains a slash — "ssid:Home/AA:BB:CC:DD:EE:FF" — so
	// the ID cannot be assumed to be a single path segment. Split on the known
	// action suffix instead and treat everything before it as the ID.
	id, action := path, ""
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if candidate := path[i+1:]; deviceActions[candidate] {
			id, action = path[:i], candidate
		}
	}
	if id == "" {
		http.Error(w, "device id required", http.StatusBadRequest)
		return
	}

	if action == "" {
		switch r.Method {
		case http.MethodPatch:
			s.handlePatchDevice(w, r, id)
		case http.MethodGet:
			dev, ok := s.devEngine.GetDevice(id)
			if !ok {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			writeJSON(w, dev)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if action == "history" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeviceHistory(w, r, id)
		return
	}

	if action == "rdns" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeviceRDNS(w, r, id)
		return
	}

	if action == "resolve-name" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleResolveName(w, r, id)
		return
	}

	if action == "portscan" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handlePortScan(w, r, id)
		return
	}

	if action == "enrich" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleEnrich(w, r, id)
		return
	}

	http.NotFound(w, r)
}

// handleEnrich queues a fingerprint refresh. The work runs on the enrichment
// tier, so this returns as soon as the job is accepted.
func (s *Server) handleEnrich(w http.ResponseWriter, r *http.Request, id string) {
	queued, err := s.devEngine.RequestEnrichment(id, engine.EnrichReasonManual)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	status := "enrich_started"
	if !queued {
		status = "already_running"
	}
	writeJSON(w, map[string]string{
		"status": status,
		"id":     id,
	})
}

func (s *Server) handlePatchDevice(w http.ResponseWriter, r *http.Request, id string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var patch engine.DevicePatch
	if err := json.Unmarshal(body, &patch); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	dev, err := s.devEngine.PatchDevice(id, patch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, dev)
}

func (s *Server) handleDeviceHistory(w http.ResponseWriter, r *http.Request, id string) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}

	events, err := s.devEngine.ListDeviceHistory(id, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]interface{}{
		"events": events,
	})
}

func (s *Server) handleDeviceRDNS(w http.ResponseWriter, r *http.Request, id string) {
	res, err := s.devEngine.LookupDeviceNames(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	names := make([]string, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		names = append(names, c.Hostname)
	}
	if len(names) == 0 && res.Hostname != "" {
		names = append(names, res.Hostname)
	}
	writeJSON(w, map[string]interface{}{
		"names":       names,
		"hostname":    res.Hostname,
		"name_source": res.NameSource,
		"candidates":  res.Candidates,
	})
}

func (s *Server) handleResolveName(w http.ResponseWriter, r *http.Request, id string) {
	res, err := s.devEngine.ResolveDeviceName(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request, id string) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "common"
	}
	mode = strings.ToLower(mode)

	started, err := s.devEngine.TryStartPortScan(r.Context(), id, mode)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !started {
		writeJSON(w, map[string]string{
			"status": "already_running",
			"id":     id,
			"mode":   mode,
		})
		return
	}

	writeJSON(w, map[string]string{
		"status": "scan_started",
		"id":     id,
		"mode":   mode,
	})
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info, err := network.GetActiveNetworkInfo()
	if err != nil {
		http.Error(w, fmt.Sprintf("Network interface error: %v", err), http.StatusInternalServerError)
		return
	}

	go func() {
		_, _ = s.devEngine.PerformScan(context.Background(), info)
	}()

	writeJSON(w, map[string]string{
		"status":  "scan_started",
		"message": "Subnet discovery scan launched",
	})
}

func (s *Server) handleDHCPImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	leases := dhcp.Parse(body)
	if len(leases) == 0 {
		http.Error(w, "No DHCP leases found in payload", http.StatusBadRequest)
		return
	}
	res := s.devEngine.ImportDHCPLeases(leases)
	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"created": res.Created,
		"updated": res.Updated,
		"skipped": res.Skipped,
		"parsed":  len(leases),
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.devEngine.GetSettings())
	case http.MethodPut:
		var patch engine.SettingsPatch
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&patch); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		out, err := s.devEngine.UpdateSettings(patch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleEventsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := s.devEngine.ListEvents("", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"events": events})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan string, 50)

	s.sseMu.Lock()
	s.sseClients[clientChan] = true
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, clientChan)
		s.sseMu.Unlock()
	}()

	initialBytes, _ := json.Marshal(map[string]interface{}{
		"devices":     s.devEngine.GetDevices(),
		"is_scanning": s.devEngine.IsScanning(),
	})
	fmt.Fprintf(w, "event: init\ndata: %s\n\n", string(initialBytes))
	w.(http.Flusher).Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-clientChan:
			fmt.Fprint(w, msg)
			w.(http.Flusher).Flush()
		}
	}
}

func (s *Server) broadcastSSE(eventType string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Error("SSE marshal error", "error", err)
		return
	}

	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(payload))

	s.sseMu.RLock()
	defer s.sseMu.RUnlock()

	for clientChan := range s.sseClients {
		select {
		case clientChan <- msg:
		default:
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := notify.Show("Gofing", "Test alert: local network notifications are working!")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "message": "Notification sent"})
}
