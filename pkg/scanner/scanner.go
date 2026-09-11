package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
type Scanner struct {
	// Cached `arp` parses, kept separately for the numeric and name-resolving
	// forms because they cost three orders of magnitude apart. A pass used to
	// exec arp two or three times within a couple of seconds; the kernel table
	// does not change meaningfully at that granularity.
	arpMu      sync.Mutex
	arpNumeric arpCache
	arpNamed   arpCache

	// arpExecFn overrides the `arp` exec for tests. numeric mirrors the flag
	// the real implementation would have used.
	arpExecFn func(ctx context.Context, numeric bool) ([]RawDevice, error)
}

type arpCache struct {
	rows []RawDevice
	at   time.Time
}

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
		return nil, fmt.Errorf("expand CIDR: %w", err)
	}

	toProbe := filterSkippedIPs(ips, skipHits)
	pingResults := s.pingSweep(ctx, toProbe, progressCb)
	applySkipHits(pingResults, skipHits)

	arpByIP := make(map[string]RawDevice)
	// Fresh exec: the sweep above is what provoked these ARP entries. Numeric,
	// because a ten-second reverse-resolve pass would dominate the sweep and
	// the enrichment tier resolves names properly anyway.
	arpDevices, err := s.ARPTableNumeric(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("parse ARP table: %w", err)
	}
	for _, dev := range arpDevices {
		arpByIP[dev.IP] = dev
	}

	return mergeProbeAndARP(pingResults, arpByIP, subnetCIDR, iface, time.Now()), nil
}

// ARPTable returns rows from macOS `arp -an`, always freshly exec'd.
func (s *Scanner) ARPTable(ctx context.Context) ([]RawDevice, error) {
	return s.ARPTableNumeric(ctx, 0)
}

// ARPTableNumeric returns `arp -an` rows: IP, MAC and interface, with no
// hostnames. This is the form to use for presence and sweeps.
//
// `arp -a` reverse-resolves every entry, which on a /24 with mostly
// unresolvable addresses takes ten seconds or more — versus about ten
// milliseconds for `-an`. Layer-2 presence does not need names, and since
// enrichment now resolves names properly, nothing else has to pay that cost.
func (s *Scanner) ARPTableNumeric(ctx context.Context, maxAge time.Duration) ([]RawDevice, error) {
	return s.arpTable(ctx, maxAge, true)
}

// ARPTableCached returns `arp -a` rows, including the Bonjour hostnames macOS
// has cached, reusing a previous result when it is newer than maxAge.
//
// This form is slow — it reverse-resolves every entry. Use it only when a
// hostname is the point; prefer ARPTableNumeric otherwise.
func (s *Scanner) ARPTableCached(ctx context.Context, maxAge time.Duration) ([]RawDevice, error) {
	return s.arpTable(ctx, maxAge, false)
}

func (s *Scanner) arpTable(ctx context.Context, maxAge time.Duration, numeric bool) ([]RawDevice, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.arpMu.Lock()
	defer s.arpMu.Unlock()

	cache := &s.arpNamed
	if numeric {
		cache = &s.arpNumeric
	}
	if maxAge > 0 && !cache.at.IsZero() && time.Since(cache.at) < maxAge {
		out := make([]RawDevice, len(cache.rows))
		copy(out, cache.rows)
		return out, nil
	}

	exec := s.arpExecFn
	if exec == nil {
		exec = s.parsemacOSARPTable
	}
	rows, err := exec(ctx, numeric)
	if err != nil {
		return nil, err
	}
	cache.rows = make([]RawDevice, len(rows))
	copy(cache.rows, rows)
	cache.at = time.Now()
	return rows, nil
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

// mergeProbeAndARP returns hosts on the scanned subnet, evidenced by a complete
// ARP entry. The ping sweep's job is to provoke ARP resolution for every
// address and to measure latency; the ARP table is what decides who exists.
//
// A probe reply is NOT accepted on its own. On a directly-connected subnet a
// host cannot exchange IP packets without a resolved ARP entry, so a
// "reachable" address with no complete row is a probe artifact — and under the
// sweep's 48-way concurrency macOS produces them readily: measured on a quiet
// /24, five addresses reported sub-millisecond TCP connects while being
// unreachable to any serial probe and sitting at `(incomplete)` in the ARP
// table. Trusting those replies invented a phantom device per address, each
// one MAC-less, nameless and permanently offline, and marked genuinely absent
// devices online for a sweep at a time.
//
// Stale ARP may linger until the OS expires it; the presence tier's
// verification pass is what retires those.
func mergeProbeAndARP(pingResults map[string]float64, arpByIP map[string]RawDevice, subnetCIDR, iface string, now time.Time) []RawDevice {
	seen := make(map[string]bool, len(pingResults)+len(arpByIP))
	var result []RawDevice
	iface = strings.TrimSpace(iface)

	onScannedIface := func(arp RawDevice) bool {
		return iface == "" || arp.Iface == "" || strings.EqualFold(arp.Iface, iface)
	}

	for ip, lat := range pingResults {
		arp, ok := arpByIP[ip]
		if !ok || arp.MAC == "" || !onScannedIface(arp) {
			// No Layer-2 evidence: discard rather than report a host.
			continue
		}
		seen[ip] = true
		result = append(result, RawDevice{
			IP:        ip,
			MAC:       arp.MAC,
			Iface:     arp.Iface,
			Hostname:  arp.Hostname,
			LatencyMs: lat,
			IsOnline:  true,
			LastSeen:  now,
		})
	}

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
		if !onScannedIface(arp) {
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
				if isTCPRefused(err) {
					select {
					case hit <- struct{}{}:
						cancel()
					default:
					}
				}
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

func isTCPRefused(err error) bool {
	if err == nil {
		return false
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && sysErr == syscall.ECONNREFUSED {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func pingIPFast(ctx context.Context, ip string) (float64, bool) {
	// TCP probes first, all ports at once. Dialing them in sequence cost ~800ms
	// per unreachable host — the dominant term in a /24 sweep — for no more
	// coverage than a single parallel fan-out with a slightly longer timeout.
	start := time.Now()
	if probeTCPParallel(ctx, ip, 150*time.Millisecond) {
		return float64(time.Since(start).Microseconds()) / 1000.0, true
	}

	// ICMP with one retry. macOS ping -W is milliseconds to wait for a reply.
	if lat, ok := pingOnce(ctx, ip, 400*time.Millisecond); ok {
		return lat, true
	}
	return pingOnce(ctx, ip, 500*time.Millisecond)
}

// ProbeIPVerify is the patient reachability check used to confirm or retire a
// device that Layer-2 (ARP) still vouches for.
//
// Power-saving devices — phones, tablets, watches — duty-cycle their Wi-Fi
// radio on roughly a 0.3-0.5s period, and many answer no TCP port at all, so
// ICMP is the only signal. A single packet, or several packets spaced closely
// together, all land in the same sleep window and are simply lost: measured
// against a sleeping iPad, `-c 1 -W 400` hit 0/8 and `-c 3 -i 0.2` hit 1/8,
// while `-c 3 -i 0.5` hit 8/8. Spacing the packets across separate wake
// windows is what makes the probe reliable.
//
// Costs ~1-2s, so call it on a slow cadence, not every presence pass.
func ProbeIPVerify(ctx context.Context, ip string) (float64, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	// A more patient TCP window than the quick probe: this LAN shows RTTs up to
	// ~190ms, where a 100ms dial gives up too early.
	if ok := probeTCPParallel(ctx, ip, 300*time.Millisecond); ok {
		return float64(time.Since(start).Microseconds()) / 1000.0, true
	}
	return pingPackets(ctx, ip, time.Second, verifyPingCount, verifyPingInterval)
}

// Verification ping shape. The interval must exceed a power-saving radio's
// sleep window; 500ms is empirically sufficient and stays unprivileged
// (macOS restricts `-i` below 0.1s to root).
const (
	verifyPingCount    = 3
	verifyPingInterval = 500 * time.Millisecond
)

func pingOnce(parentCtx context.Context, ip string, timeout time.Duration) (float64, bool) {
	return pingPackets(parentCtx, ip, timeout, 1, 0)
}

// pingPackets sends count ICMP echoes spaced interval apart, succeeding if any
// is answered. timeout is the per-reply wait (`ping -W`).
func pingPackets(parentCtx context.Context, ip string, timeout time.Duration, count int, interval time.Duration) (float64, bool) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	if count < 1 {
		count = 1
	}

	// Budget: every inter-packet gap, plus the final reply wait, plus slack for
	// process spawn. Too tight a budget kills ping before its last packet and
	// silently turns a reachable host into a miss.
	budget := timeout + 200*time.Millisecond
	if count > 1 {
		budget += time.Duration(count-1) * interval
	}
	ctx, cancel := context.WithTimeout(parentCtx, budget)
	defer cancel()

	waitMs := int(timeout / time.Millisecond)
	if waitMs < 1 {
		waitMs = 1
	}
	args := []string{"-c", strconv.Itoa(count), "-W", strconv.Itoa(waitMs)}
	if count > 1 && interval > 0 {
		args = append(args, "-i", strconv.FormatFloat(interval.Seconds(), 'f', -1, 64))
	}
	args = append(args, ip)
	cmd := exec.CommandContext(ctx, "ping", args...)
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

func (s *Scanner) parsemacOSARPTable(ctx context.Context, numeric bool) ([]RawDevice, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// `-a` includes mDNS/Bonjour hostnames when macOS has them cached, at the
	// cost of a reverse lookup per entry.
	// On macOS, `-n -l -a` includes linklayer reachability (expirations & probe retries)
	// without hostname reverse-lookups. `-an` is used as a fallback if `-l` is unsupported.
	args := []string{"-a"}
	if numeric {
		args = []string{"-n", "-l", "-a"}
	}
	cmd := exec.CommandContext(ctx, "arp", args...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		if numeric {
			out.Reset()
			cmd = exec.CommandContext(ctx, "arp", "-an")
			cmd.Stdout = &out
			if err := cmd.Run(); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return parseARPTableOutput(out.String(), time.Now()), nil
}

// ARPHostname returns the Bonjour/mDNS name for ip from `arp -a`, if present.
func (s *Scanner) ARPHostname(ip string) string {
	devices, err := s.ARPTableCached(context.Background(), 2*time.Second)
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
		if line == "" || strings.HasPrefix(line, "Neighbor") {
			continue
		}

		var ip, macRaw, iface, hostname string
		var expired bool

		// Check Format 1: `arp -n -l -a`
		// e.g. "192.168.0.1 54:af:97:14:cf:7c 2m38s 2m30s en0 1"
		fields := strings.Fields(line)
		if len(fields) >= 5 && net.ParseIP(fields[0]) != nil {
			ip = fields[0]
			macRaw = fields[1]
			expO := strings.ToLower(fields[2])
			expI := strings.ToLower(fields[3])
			iface = fields[4]
			prbs := ""
			if len(fields) >= 7 {
				prbs = fields[6]
			}

			// An ARP entry is dead/unreachable if:
			// 1) Both outgoing and incoming timers expired (exp_o == expired && exp_i == expired)
			// 2) Incoming traffic expired and kernel ARP probe retries failed (exp_i == expired && prbs > 0)
			if expO == "expired" && expI == "expired" {
				expired = true
			}
			if expI == "expired" && prbs != "" && prbs != "0" {
				expired = true
			}
		} else if matches := arpLineRe.FindStringSubmatch(line); len(matches) >= 5 {
			// Format 2: classic `arp -a` / `arp -an`
			// e.g. "? (192.168.0.1) at 54:af:97:14:cf:7c on en0 ..."
			if matches[1] != "?" {
				hostname = matches[1]
			}
			ip = matches[2]
			macRaw = matches[3]
			iface = matches[4]
		} else {
			continue
		}

		if expired || macRaw == "(incomplete)" {
			continue
		}

		formattedMAC := formatMAC(macRaw)
		if formattedMAC == "FF:FF:FF:FF:FF:FF" ||
			strings.HasPrefix(formattedMAC, "01:00:5E") || strings.HasPrefix(formattedMAC, "33:33:") ||
			isMulticastIP(ip) {
			continue
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
