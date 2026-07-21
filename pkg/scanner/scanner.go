package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RawDevice represents basic information obtained from a network scan.
type RawDevice struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname,omitempty"` // from macOS `arp -a` when known
	Iface     string    `json:"iface"`
	LatencyMs float64   `json:"latency_ms"`
	IsOnline  bool      `json:"is_online"`
	LastSeen  time.Time `json:"last_seen"`
}

// Scanner handles IP ping sweeps and macOS ARP cache extraction.
type Scanner struct{}

// New returns a new Scanner instance.
func New() *Scanner {
	return &Scanner{}
}

// PerformScan executes a ping sweep across the subnet, then uses the ARP table
// only to enrich MAC addresses. A host is considered present only if it
// responded to a reachability probe — stale ARP cache entries alone are not
// enough (macOS retains ARP rows for minutes after a device disconnects).
func (s *Scanner) PerformScan(subnetCIDR string, progressCb func(scannedCount, total int)) ([]RawDevice, error) {
	ips, err := expandCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %w", err)
	}

	// 1. Fast Ping Sweep across subnet using parallel worker pool
	pingResults := s.pingSweep(ips, progressCb)

	// 2. Parse macOS ARP table for MAC enrichment only
	arpByIP := make(map[string]RawDevice)
	arpDevices, err := s.parsemacOSARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ARP table: %w", err)
	}
	for _, dev := range arpDevices {
		arpByIP[dev.IP] = dev
	}

	return mergeProbeAndARP(pingResults, arpByIP, time.Now()), nil
}

// mergeProbeAndARP returns only hosts that answered a probe, enriched with ARP MAC/hostname.
// ARP-only entries (stale cache) are intentionally excluded.
func mergeProbeAndARP(pingResults map[string]float64, arpByIP map[string]RawDevice, now time.Time) []RawDevice {
	var result []RawDevice
	for ip, lat := range pingResults {
		dev := RawDevice{
			IP:        ip,
			LatencyMs: lat,
			IsOnline:  true,
			LastSeen:  now,
		}
		if arp, ok := arpByIP[ip]; ok {
			dev.MAC = arp.MAC
			dev.Iface = arp.Iface
			dev.Hostname = arp.Hostname
		}
		result = append(result, dev)
	}
	return result
}

func (s *Scanner) pingSweep(ips []string, progressCb func(scanned, total int)) map[string]float64 {
	results := make(map[string]float64)
	var mu sync.Mutex

	total := len(ips)
	var processed int32

	// Moderate concurrency — 128 parallel probes floods Wi‑Fi and causes false misses.
	concurrency := 48
	ipChan := make(chan string, total)
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				lat, ok := pingIPFast(ip)

				curr := atomic.AddInt32(&processed, 1)

				if ok {
					mu.Lock()
					results[ip] = lat
					mu.Unlock()
				}

				if progressCb != nil && (curr%15 == 0 || int(curr) == total) {
					progressCb(int(curr), total)
				}
			}
		}()
	}

	wg.Wait()
	return results
}

func pingIPFast(ip string) (float64, bool) {
	// TCP probes first — moderately patient to avoid Wi‑Fi false negatives.
	commonPorts := []string{"80", "443", "22", "445", "53", "8080", "548", "5000"}
	start := time.Now()

	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			lat := float64(time.Since(start).Microseconds()) / 1000.0
			return lat, true
		}
	}

	// ICMP with one retry. macOS ping -W is milliseconds to wait for a reply.
	if lat, ok := pingOnce(ip, 400*time.Millisecond); ok {
		return lat, true
	}
	return pingOnce(ip, 500*time.Millisecond)
}

func pingOnce(ip string, timeout time.Duration) (float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+200*time.Millisecond)
	defer cancel()

	waitMs := int(timeout / time.Millisecond)
	if waitMs < 1 {
		waitMs = 1
	}
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(waitMs), ip)
	var out bytes.Buffer
	cmd.Stdout = &out

	startPing := time.Now()
	err := cmd.Run()
	duration := time.Since(startPing)

	if err == nil {
		rtt := parsePingLatency(out.String())
		if rtt > 0 {
			return rtt, true
		}
		return float64(duration.Milliseconds()), true
	}
	return 0, false
}

var pingTimeRe = regexp.MustCompile(`time=([\d\.]+)\s*ms`)

func parsePingLatency(output string) float64 {
	matches := pingTimeRe.FindStringSubmatch(output)
	if len(matches) >= 2 {
		if val, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return val
		}
	}
	return 0
}

// arpLineRe matches both:
//
//	? (192.168.0.1) at aa:bb:... on en0 ...
//	amys-mbp.local (192.168.0.142) at 8c:85:... on en0 ...
//
// Use `arp -a` (not -an) so Bonjour names are present when macOS knows them.
var arpLineRe = regexp.MustCompile(`^(\S+)\s+\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\w+)`)

func (s *Scanner) parsemacOSARPTable() ([]RawDevice, error) {
	// `-a` (not `-n`) includes mDNS/Bonjour hostnames when cached.
	cmd := exec.Command("arp", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return parseARPTableOutput(out.String(), time.Now()), nil
}

// ARPHostname returns the Bonjour/mDNS name for ip from `arp -a`, if present.
func (s *Scanner) ARPHostname(ip string) string {
	devices, err := s.parsemacOSARPTable()
	if err != nil {
		return ""
	}
	for _, d := range devices {
		if d.IP == ip && d.Hostname != "" {
			return d.Hostname
		}
	}
	return ""
}

func parseARPTableOutput(text string, now time.Time) []RawDevice {
	var devices []RawDevice
	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := arpLineRe.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}
		name := matches[1]
		ip := matches[2]
		macRaw := matches[3]
		iface := matches[4]

		formattedMAC := formatMAC(macRaw)

		if macRaw == "(incomplete)" || formattedMAC == "FF:FF:FF:FF:FF:FF" ||
			strings.HasPrefix(formattedMAC, "01:00:5E") || strings.HasPrefix(formattedMAC, "33:33:") ||
			isMulticastIP(ip) {
			continue
		}

		hostname := ""
		if name != "?" {
			hostname = name
		}

		devices = append(devices, RawDevice{
			IP:       ip,
			MAC:      formattedMAC,
			Hostname: hostname,
			Iface:    iface,
			IsOnline: true,
			LastSeen: now,
		})
	}

	return devices
}

func isMulticastIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	return parsed.IsMulticast() || parsed.IsUnspecified() || parsed.IsLinkLocalMulticast()
}

func formatMAC(macStr string) string {
	parts := strings.Split(macStr, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		} else {
			parts[i] = p
		}
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
