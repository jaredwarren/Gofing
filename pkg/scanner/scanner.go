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

// PerformScan executes a ping sweep across the subnet to populate ARP, then reads the ARP table.
func (s *Scanner) PerformScan(subnetCIDR string, progressCb func(scannedCount, total int)) ([]RawDevice, error) {
	ips, err := expandCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %w", err)
	}

	// 1. Fast Ping Sweep across subnet using parallel worker pool
	pingResults := s.pingSweep(ips, progressCb)

	// 2. Parse macOS ARP table
	arpDevices, err := s.parsemacOSARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ARP table: %w", err)
	}

	// Combine ping results with ARP table
	deviceMap := make(map[string]*RawDevice)

	// Add ARP devices
	for _, dev := range arpDevices {
		devCopy := dev
		deviceMap[dev.IP] = &devCopy
	}

	// Enrich/Add ping sweep results
	now := time.Now()
	for ip, lat := range pingResults {
		if dev, exists := deviceMap[ip]; exists {
			dev.IsOnline = true
			dev.LatencyMs = lat
			dev.LastSeen = now
		} else {
			// Device responded to ping but MAC wasn't in ARP
			deviceMap[ip] = &RawDevice{
				IP:        ip,
				MAC:       "",
				LatencyMs: lat,
				IsOnline:  true,
				LastSeen:  now,
			}
		}
	}

	// Convert map to slice
	var result []RawDevice
	for _, dev := range deviceMap {
		result = append(result, *dev)
	}

	return result, nil
}

func (s *Scanner) pingSweep(ips []string, progressCb func(scanned, total int)) map[string]float64 {
	results := make(map[string]float64)
	var mu sync.Mutex

	total := len(ips)
	var processed int32

	// High concurrency worker pool for sub-second sweep
	concurrency := 128
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
	// 1. Try TCP probe on common ports with 50ms timeout
	commonPorts := []string{"80", "443", "22", "445", "53", "8080"}
	start := time.Now()

	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 40*time.Millisecond)
		if err == nil {
			conn.Close()
			lat := float64(time.Since(start).Microseconds()) / 1000.0
			return lat, true
		}
	}

	// 2. Native macOS ping with strict 150ms Context Timeout (NO -W 150 which macOS treats as 150 SECONDS!)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", ip)
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

var arpLineRe = regexp.MustCompile(`\?\s+\(([\d\.]+)\)\s+at\s+([a-fA-F0-9:]+)\s+on\s+(\w+)`)

func (s *Scanner) parsemacOSARPTable() ([]RawDevice, error) {
	cmd := exec.Command("arp", "-an")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var devices []RawDevice
	scanner := bufio.NewScanner(&out)
	now := time.Now()

	for scanner.Scan() {
		line := scanner.Text()
		matches := arpLineRe.FindStringSubmatch(line)
		if len(matches) >= 4 {
			ip := matches[1]
			macRaw := matches[2]
			iface := matches[3]

			formattedMAC := formatMAC(macRaw)

			// Filter out incomplete, broadcast, or IPv4/IPv6 Multicast MACs (01:00:5E:... / 33:33:...)
			if macRaw == "(incomplete)" || formattedMAC == "FF:FF:FF:FF:FF:FF" ||
				strings.HasPrefix(formattedMAC, "01:00:5E") || strings.HasPrefix(formattedMAC, "33:33:") ||
				isMulticastIP(ip) {
				continue
			}

			devices = append(devices, RawDevice{
				IP:        ip,
				MAC:       formattedMAC,
				Iface:     iface,
				IsOnline:  true,
				LastSeen:  now,
				LatencyMs: 0,
			})
		}
	}

	return devices, nil
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
