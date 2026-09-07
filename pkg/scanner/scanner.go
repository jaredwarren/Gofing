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

// commonTCPPorts are tried for cheap reachability (full sweep and quick probe).
var commonTCPPorts = []string{"80", "443", "22", "445", "53", "8080", "548", "5000"}

// PerformScan executes a ping sweep across the subnet, then reads the ARP table.
// Presence is the union of: hosts that answered ICMP/TCP, and complete in-subnet
// ARP rows on iface (Layer-2 evidence for devices that ignore ping).
// skipHits are IPs already confirmed online (presence-first); they are not
// re-probed but are treated as ping hits so ARP merge and fingerprinting still run.
func (s *Scanner) PerformScan(ctx context.Context, subnetCIDR, iface string, skipHits map[string]float64, progressCb func(scannedCount, total int)) ([]RawDevice, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ips, err := expandCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %w", err)
	}

	toProbe := filterSkippedIPs(ips, skipHits)
	pingResults := s.pingSweep(ctx, toProbe, progressCb)
	applySkipHits(pingResults, skipHits)

	arpByIP := make(map[string]RawDevice)
	arpDevices, err := s.parsemacOSARPTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ARP table: %w", err)
	}
	for _, dev := range arpDevices {
		arpByIP[dev.IP] = dev
	}

	return mergeProbeAndARP(pingResults, arpByIP, subnetCIDR, iface, time.Now()), nil
}

// ARPTable returns complete rows from macOS `arp -a`.
func (s *Scanner) ARPTable(ctx context.Context) ([]RawDevice, error) {
	return s.parsemacOSARPTable(ctx)
}

func filterSkippedIPs(ips []string, skipHits map[string]float64) []string {
	if len(skipHits) == 0 {
		return ips
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, skip := skipHits[ip]; skip {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func applySkipHits(pingResults, skipHits map[string]float64) {
	for ip, lat := range skipHits {
		if _, ok := pingResults[ip]; ok {
			continue
		}
		pingResults[ip] = lat
	}
}

// mergeProbeAndARP returns probe-responsive hosts plus complete ARP entries that
// sit on the scanned subnet (and iface, when set). The ping sweep already
// provoked ARP for every address; a complete row is L2 evidence even when ICMP
// and TCP are blocked. Stale ARP may linger until the OS expires it.
func mergeProbeAndARP(pingResults map[string]float64, arpByIP map[string]RawDevice, subnetCIDR, iface string, now time.Time) []RawDevice {
	seen := make(map[string]bool, len(pingResults)+len(arpByIP))
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
		seen[ip] = true
		result = append(result, dev)
	}

	iface = strings.TrimSpace(iface)
	for ip, arp := range arpByIP {
		if seen[ip] {
			continue
		}
		if arp.MAC == "" {
			continue
		}
		if subnetCIDR != "" && !ipInCIDR(ip, subnetCIDR) {
			continue
		}
		if iface != "" && arp.Iface != "" && !strings.EqualFold(arp.Iface, iface) {
			continue
		}
		arp.IsOnline = true
		arp.LastSeen = now
		result = append(result, arp)
	}
	return result
}

func ipInCIDR(ipStr, cidr string) bool {
	if ipStr == "" || cidr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func (s *Scanner) pingSweep(ctx context.Context, ips []string, progressCb func(scanned, total int)) map[string]float64 {
	results := make(map[string]float64)
	var mu sync.Mutex

	total := len(ips)
	var processed int32

	// Moderate concurrency — 48 parallel probes to avoid Wi-Fi saturation.
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
				select {
				case <-ctx.Done():
					return
				default:
				}
				lat, ok := pingIPFast(ctx, ip)

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

// ProbeIP is a cheap reachability check for a single host (TCP common ports, then ICMP).
func ProbeIP(ctx context.Context, ip string) (float64, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	return pingIPFast(ctx, ip)
}

// ProbeIPQuick is a faster presence check for known inventory IPs: parallel TCP
// (100ms), then a single ICMP (400ms). Worst case ~0.5s vs ~1.7s for ProbeIP.
func ProbeIPQuick(ctx context.Context, ip string) (float64, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	if ok := probeTCPParallel(ctx, ip, 100*time.Millisecond); ok {
		return float64(time.Since(start).Microseconds()) / 1000.0, true
	}
	return pingOnce(ctx, ip, 400*time.Millisecond)
}

func probeTCPParallel(ctx context.Context, ip string, timeout time.Duration) bool {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hit := make(chan struct{}, 1)
	var wg sync.WaitGroup
	for _, port := range commonTCPPorts {
		wg.Add(1)
		go func(port string) {
			defer wg.Done()
			var d net.Dialer
			conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(ip, port))
			if err != nil {
				return
			}
			_ = conn.Close()
			select {
			case hit <- struct{}{}:
				cancel()
			default:
			}
		}(port)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-hit:
		return true
	case <-done:
		return false
	case <-ctx.Done():
		return false
	}
}

func pingIPFast(ctx context.Context, ip string) (float64, bool) {
	// TCP probes first — moderately patient to avoid Wi‑Fi false negatives.
	start := time.Now()

	for _, port := range commonTCPPorts {
		var d net.Dialer
		d.Timeout = 100 * time.Millisecond
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if err == nil {
			conn.Close()
			lat := float64(time.Since(start).Microseconds()) / 1000.0
			return lat, true
		}
	}

	// ICMP with one retry. macOS ping -W is milliseconds to wait for a reply.
	if lat, ok := pingOnce(ctx, ip, 400*time.Millisecond); ok {
		return lat, true
	}
	return pingOnce(ctx, ip, 500*time.Millisecond)
}

func pingOnce(parentCtx context.Context, ip string, timeout time.Duration) (float64, bool) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout+200*time.Millisecond)
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

func (s *Scanner) parsemacOSARPTable(ctx context.Context) ([]RawDevice, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// `-a` (not `-n`) includes mDNS/Bonjour hostnames when cached.
	cmd := exec.CommandContext(ctx, "arp", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return parseARPTableOutput(out.String(), time.Now()), nil
}

// ARPHostname returns the Bonjour/mDNS name for ip from `arp -a`, if present.
func (s *Scanner) ARPHostname(ip string) string {
	devices, err := s.parsemacOSARPTable(context.Background())
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
