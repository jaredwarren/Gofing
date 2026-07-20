package server

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
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

	// Register SSE broadcast listener with engine
	devEngine.RegisterEventListener(func(eventType string, data interface{}) {
		srv.broadcastSSE(eventType, data)
	})

	return srv
}

// Handler returns the http.Handler for all endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/network", s.handleNetworkInfo)
	mux.HandleFunc("/api/devices", s.handleGetDevices)
	mux.HandleFunc("/api/scan", s.handleTriggerScan)
	mux.HandleFunc("/api/events", s.handleSSE)

	// Static UI assets
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

func (s *Server) handleGetDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.devEngine.GetDevices()
	writeJSON(w, map[string]interface{}{
		"devices":     devices,
		"is_scanning": s.devEngine.IsScanning(),
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

	// Send initial state message
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
			// Buffer full, skip message for slow client
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
