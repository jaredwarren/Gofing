package ports

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ServicePort defines a well-known TCP port and human-readable name.
type ServicePort struct {
	Port int    `json:"port"`
	Name string `json:"name"`
}

var CommonPorts = []ServicePort{
	{22, "SSH"},
	{53, "DNS"},
	{80, "HTTP"},
	{139, "NetBIOS"},
	{443, "HTTPS"},
	{445, "SMB Share"},
	{631, "IPP Printer"},
	{1883, "MQTT Smart Home"},
	{3389, "RDP"},
	{5000, "Synology DSM"},
	{5900, "VNC Desktop"},
	{8080, "Web Admin"},
	{8123, "Home Assistant"},
	{32400, "Plex Media Server"},
}

// ScanPorts probes the target IP for open common ports in parallel.
func ScanPorts(ip string) []ServicePort {
	var open []ServicePort
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range CommonPorts {
		wg.Add(1)
		go func(sp ServicePort) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, sp.Port)
			conn, err := net.DialTimeout("tcp", addr, 80*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, sp)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})

	return open
}
