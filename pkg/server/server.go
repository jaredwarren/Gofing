package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
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
	mux.HandleFunc("/api/events", s.handleSSE)

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
	})
}

// handleDeviceSubpath serves /api/devices/{id} and /api/devices/{id}/history.
func (s *Server) handleDeviceSubpath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	parts := strings.Split(path, "/")
	id := parts[0]
	if id == "" {
		http.Error(w, "device id required", http.StatusBadRequest)
		return
	}

	if len(parts) == 1 {
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

	if len(parts) == 2 && parts[1] == "history" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeviceHistory(w, r, id)
		return
	}

	if len(parts) == 2 && parts[1] == "rdns" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeviceRDNS(w, r, id)
		return
	}

	if len(parts) == 2 && parts[1] == "resolve-name" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleResolveName(w, r, id)
		return
	}

	if len(parts) == 2 && parts[1] == "portscan" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handlePortScan(w, r, id)
		return
	}

	http.NotFound(w, r)
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

	started, err := s.devEngine.TryStartPortScan(id, mode)
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
		_, _ = s.devEngine.PerformScan(info)
	}()

	writeJSON(w, map[string]string{
		"status":  "scan_started",
		"message": "Subnet discovery scan launched",
	})
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
		close(clientChan)
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
		log.Printf("SSE marshal error: %v", err)
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
