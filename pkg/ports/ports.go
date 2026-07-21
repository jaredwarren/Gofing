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

// CommonPorts is the fast default probe set used by ScanPorts.
var CommonPorts = []ServicePort{
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{53, "DNS"},
	{80, "HTTP"},
	{110, "POP3"},
	{139, "NetBIOS"},
	{143, "IMAP"},
	{443, "HTTPS"},
	{445, "SMB Share"},
	{548, "AFP"},
	{631, "IPP Printer"},
	{993, "IMAPS"},
	{995, "POP3S"},
	{1883, "MQTT Smart Home"},
	{3389, "RDP"},
	{5000, "Synology DSM / UPnP"},
	{5353, "mDNS"},
	{5480, "Web Admin"},
	{5900, "VNC Desktop"},
	{8080, "Web Admin"},
	{8123, "Home Assistant"},
	{8291, "MikroTik Winbox"},
	{8443, "HTTPS Alt"},
	{9100, "Raw Print"},
	{32400, "Plex Media Server"},
	{62078, "iOS Wireless Sync"},
}

// MaxDeepPorts caps how many ports a single deep scan may probe.
const MaxDeepPorts = 1024

// DefaultDeepRange is used when mode=deep with no custom bounds.
const DefaultDeepStart = 1
const DefaultDeepEnd = 1024

var wellKnownNames = map[int]string{}

func init() {
	for _, p := range CommonPorts {
		wellKnownNames[p.Port] = p.Name
	}
	extras := map[int]string{
		135: "MSRPC", 389: "LDAP", 636: "LDAPS", 1433: "MSSQL", 1521: "Oracle",
		3306: "MySQL", 5432: "PostgreSQL", 5672: "AMQP", 6379: "Redis",
		9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
	}
	for port, name := range extras {
		if _, ok := wellKnownNames[port]; !ok {
			wellKnownNames[port] = name
		}
	}
}

// PortName returns a friendly name for a port number.
func PortName(port int) string {
	if n, ok := wellKnownNames[port]; ok {
		return n
	}
	return fmt.Sprintf("TCP %d", port)
}

// ScanPorts probes the target IP for open common ports in parallel.
func ScanPorts(ip string) []ServicePort {
	return scanPortList(ip, CommonPorts, 64, 80*time.Millisecond)
}

// ScanPortsRange probes TCP ports in [start, end] inclusive.
// Range size is capped at MaxDeepPorts (truncated from start if needed).
func ScanPortsRange(ip string, start, end int, concurrency int, timeout time.Duration) []ServicePort {
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if end < start {
		return nil
	}
	if end-start+1 > MaxDeepPorts {
		end = start + MaxDeepPorts - 1
		if end > 65535 {
			end = 65535
		}
	}
	if concurrency < 1 {
		concurrency = 64
	}
	if concurrency > 256 {
		concurrency = 256
	}
	if timeout <= 0 {
		timeout = 80 * time.Millisecond
	}

	list := make([]ServicePort, 0, end-start+1)
	for p := start; p <= end; p++ {
		list = append(list, ServicePort{Port: p, Name: PortName(p)})
	}
	return scanPortList(ip, list, concurrency, timeout)
}

func scanPortList(ip string, list []ServicePort, concurrency int, timeout time.Duration) []ServicePort {
	if ip == "" || len(list) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 32
	}

	var open []ServicePort
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(sp ServicePort) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", sp.Port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				open = append(open, sp)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	return DedupSort(open)
}

// DedupSort sorts by port ascending and removes duplicate ports.
func DedupSort(in []ServicePort) []ServicePort {
	if len(in) == 0 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		return in[i].Port < in[j].Port
	})
	out := make([]ServicePort, 0, len(in))
	var last int
	for i, sp := range in {
		if i > 0 && sp.Port == last {
			continue
		}
		out = append(out, sp)
		last = sp.Port
	}
	return out
}
