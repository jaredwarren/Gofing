package mdns

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// DeviceDetails contains resolved hostnames, friendly names, and inferred device types.
type DeviceDetails struct {
	Hostname   string   `json:"hostname"`
	NameSource string   `json:"name_source,omitempty"`
	DeviceType string   `json:"device_type"`
	Icon       string   `json:"icon"`
	Model      string   `json:"model"`
	Services   []string `json:"services"`
}

// NameLearnedFunc is invoked when the always-on listener stores a hostname for an IP.
type NameLearnedFunc func(ip, hostname, source string)

// Resolver handles hostname resolution and multi-layer device fingerprinting.
type Resolver struct {
	mdnsCache map[string]string           // service instance names
	ipNames   map[string]cachedName       // IP → best Bonjour/DNS name
	ipHints   map[string]FingerprintHints // IP → TXT-derived model/type
	cacheMu   sync.RWMutex
	onLearned NameLearnedFunc

	listenMu     sync.Mutex
	listenCancel context.CancelFunc
	listenIface  string
}

// New returns a new Resolver. Call Listen to join mDNS multicast.
func New() *Resolver {
	return &Resolver{
		mdnsCache: make(map[string]string),
		ipNames:   make(map[string]cachedName),
		ipHints:   make(map[string]FingerprintHints),
	}
}

// SetNameLearnedHandler registers a callback for newly cached mDNS hostnames.
func (r *Resolver) SetNameLearnedHandler(fn NameLearnedFunc) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.onLearned = fn
}

// ResolveInput bundles everything fingerprinting needs to know about one host.
type ResolveInput struct {
	IP               string
	MAC              string
	Vendor           string
	IsGateway        bool
	HostComputerName string
	ARPHostname      string
}

// GatewayDetails returns the fixed router fingerprint. Extracted from the
// isGateway short-circuit so a caller can identify the gateway without probing.
func GatewayDetails(vendor string) DeviceDetails {
	return DeviceDetails{
		Hostname:   "Network Gateway",
		NameSource: NameSourceHost,
		DeviceType: "Router",
		Icon:       "router",
		Model:      vendor + " Gateway",
		Services:   []string{"Gateway", "DNS", "DHCP"},
	}
}

// ResolveDevice performs multi-layer non-blocking fingerprinting.
// arpHostname is an optional name from macOS `arp -a` (Bonjour cache).
func (r *Resolver) ResolveDevice(ip string, mac string, vendor string, isGateway bool, hostComputerName string, arpHostname string) DeviceDetails {
	return r.ResolveDeviceCtx(context.Background(), ResolveInput{
		IP:               ip,
		MAC:              mac,
		Vendor:           vendor,
		IsGateway:        isGateway,
		HostComputerName: hostComputerName,
		ARPHostname:      arpHostname,
	})
}

// ResolveDeviceCtx fingerprints one host, honouring ctx throughout.
//
// The three independent network probes — the iOS sync port, reverse DNS /
// dns-sd PTR, and NetBIOS — run concurrently rather than in sequence. They
// contend for nothing and their results are merged with the same precedence
// as before, so the pass costs about as long as its slowest probe (~1.2s)
// instead of their sum (~1.4s), and far less when a free source already
// supplied the name.
func (r *Resolver) ResolveDeviceCtx(ctx context.Context, in ResolveInput) DeviceDetails {
	if ctx == nil {
		ctx = context.Background()
	}
	ip, mac, vendor := in.IP, in.MAC, in.Vendor
	isGateway, hostComputerName, arpHostname := in.IsGateway, in.HostComputerName, in.ARPHostname

	if isGateway {
		return GatewayDetails(vendor)
	}

	hostname := ""
	nameSource := NameSourceNone
	var services []string
	var detectedModel string
	var detectedType string
	var detectedIcon string

	// Priority 1: Host Mac Detection
	if hostComputerName != "" {
		if h := SanitizeHostname(hostComputerName); h != "" {
			hostname = h
			nameSource = NameSourceHost
			detectedType = "Computer"
			detectedIcon = "laptop"
			detectedModel = "Apple Mac"
		}
	}

	// Priority 2: ARP / Bonjour name already known to macOS
	if hostname == "" {
		if h := normalizeResolvedName(arpHostname); h != "" {
			hostname = h
			nameSource = NameSourceARP
			r.rememberIPName(ip, hostname, NameSourceARP)
		}
	}

	// Priority 2b: Background browse / prior deep-lookup cache
	if hostname == "" {
		if c := r.cachedForIP(ip); c.Hostname != "" {
			hostname = c.Hostname
			nameSource = c.Source
		}
	}

	// TXT / service browse fingerprint hints (model, type, services)
	if hints := r.hintsForIP(ip); hints.Model != "" || hints.DeviceType != "" || len(hints.Services) > 0 {
		services = append(services, hints.Services...)
		if detectedModel == "" && hints.Model != "" {
			detectedModel = hints.Model
		}
		if detectedType == "" && hints.DeviceType != "" {
			detectedType = hints.DeviceType
			detectedIcon = hints.Icon
		}
	}

	// The free sources above are what decide whether a name lookup is needed.
	// The iOS probe never yields a hostname, so gating on `hostname` here is
	// faithful to the original sequence.
	needName := hostname == ""

	var (
		wg      sync.WaitGroup
		isIOS   bool
		dnsName string
		dnsSrc  string
		nbName  string
	)

	// iOS sync port: type/vendor hints only, never a hostname. Always worth the
	// 40ms because it is the only signal that distinguishes an iPhone.
	wg.Add(1)
	go func() {
		defer wg.Done()
		isIOS = probeIOSSyncPortCtx(ctx, ip)
	}()

	if needName {
		// Reverse DNS / dns-sd PTR — the slowest probe, ~1.2s.
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsName, dnsSrc = r.LookupHostnameQuickCtx(ctx, ip)
		}()

		// NetBIOS. Speculative: reverse DNS outranks it, so its answer is
		// discarded when both succeed. Paying 80ms of UDP in parallel to avoid
		// 80ms of added latency on Windows hosts is the right trade.
		wg.Add(1)
		go func() {
			defer wg.Done()
			nbName = queryNetBIOSNameCtx(ctx, ip)
		}()
	}
	wg.Wait()

	// iOS probe contributes type/vendor hints only (not hostname)
	if isIOS {
		services = append(services, "iOS Wireless Sync")
		if vendor == "Private / Randomized MAC" || strings.Contains(strings.ToLower(vendor), "apple") {
			vendor = "Apple, Inc."
		}
		if detectedType == "" {
			detectedType = "Mobile Phone"
			detectedIcon = "smartphone"
			detectedModel = "Apple iPhone / iPad"
		}
	}

	// Priority 3: Reverse DNS / dns-sd PTR (quick timeout during scans)
	if hostname == "" && dnsName != "" {
		hostname = dnsName
		nameSource = dnsSrc
	}

	// Priority 4: NetBIOS (Windows PCs) — cheap UDP probe, last resort
	if hostname == "" && nbName != "" {
		hostname = nbName
		nameSource = NameSourceARP
		r.rememberIPName(ip, hostname, NameSourceARP)
	}

	inferredServices := inferServices(hostname, vendor)
	services = append(services, inferredServices...)

	devType, icon, model := classifyDevice(hostname, vendor, services, mac)
	if detectedType != "" {
		devType = detectedType
		icon = detectedIcon
		model = detectedModel
	}

	return DeviceDetails{
		Hostname:   hostname,
		NameSource: nameSource,
		DeviceType: devType,
		Icon:       icon,
		Model:      model,
		Services:   uniqueStrings(services),
	}
}

// Ultra-fast TCP probe for iOS iTunes/Finder wireless sync listener port 62078 (40ms timeout)
func probeIOSSyncPort(ip string) bool {
	return probeIOSSyncPortCtx(context.Background(), ip)
}

func probeIOSSyncPortCtx(ctx context.Context, ip string) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(ip, "62078"))
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

// normalizeResolvedName turns "AMYS-MBP.local." into "AMYS-MBP".
func normalizeResolvedName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	// Prefer the first label for .local / .lan style names.
	if i := strings.IndexByte(name, '.'); i > 0 {
		suffix := strings.ToLower(name[i+1:])
		if suffix == "local" || suffix == "lan" || suffix == "home" ||
			strings.HasSuffix(suffix, ".local") || strings.HasSuffix(suffix, ".lan") {
			name = name[:i]
		}
	}
	return SanitizeHostname(name)
}

// SanitizeHostname strips junk and rejects names that are not human-readable hostnames.
// Returns "" if the candidate should not be stored or displayed.
func SanitizeHostname(name string) string {
	name = cleanHostname(name)
	if !isSaneHostname(name) {
		return ""
	}
	return name
}

// cleanHostname removes non-printable / replacement / invalid UTF-8 bytes.
func cleanHostname(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var buf strings.Builder
	for len(name) > 0 {
		r, size := utf8.DecodeRuneInString(name)
		if r == utf8.RuneError && size == 1 {
			name = name[1:]
			continue
		}
		if r >= 0x20 && r != 0x7F && r != 0xFFFD {
			buf.WriteRune(r)
		}
		name = name[size:]
	}
	return strings.TrimSpace(buf.String())
}

// Names that are valid-looking words but come from protocol noise / dns-sd headers.
var hostnameDenylist = map[string]struct{}{
	"record": {}, "rdata": {}, "flags": {}, "domain": {}, "class": {}, "type": {},
	"add": {}, "remove": {}, "ptr": {}, "srv": {}, "txt": {}, "aaaa": {}, "arpa": {},
	"local": {}, "localhost": {}, "workgroup": {}, "msbrowse": {}, "__msbrowse__": {},
	"in-addr": {}, "ip6": {}, "ipv4": {}, "ipv6": {}, "unknown": {}, "generic": {},
}

// isSaneHostname rejects binary garbage, protocol noise, and control leftovers.
func isSaneHostname(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0xFFFD) {
		return false
	}
	if _, blocked := hostnameDenylist[strings.ToLower(name)]; blocked {
		return false
	}
	// NBNS question padding and similar (e.g. AAAAAAAAAAAAAAA) must not stick as hostnames.
	if isMonotoneASCII(name) {
		return false
	}

	lettersOrDigits := 0
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7F:
			return false
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			lettersOrDigits++
		case r == '-' || r == '_' || r == '.' || r == ' ' || r == '\'' || r == '’' || r == '(' || r == ')' || r == '/':
			// allowed punctuation for DNS / friendly names
		default:
			if r > 127 {
				lettersOrDigits++
			} else {
				return false
			}
		}
	}
	return lettersOrDigits >= 2
}

func queryNetBIOSName(ip string) string {
	return queryNetBIOSNameCtx(context.Background(), ip)
}

func queryNetBIOSNameCtx(ctx context.Context, ip string) string {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", net.JoinHostPort(ip, "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()

	req := []byte{
		0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}

	_ = conn.SetDeadline(time.Now().Add(80 * time.Millisecond))
	_, err = conn.Write(req)
	if err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	return parseNetBIOSNodeStatus(buf[:n])
}

// parseNetBIOSNodeStatus extracts a unique workstation/server name from an NBNS
// NODE STATUS (type 0x21) reply. It walks the DNS-style header/sections so the
// echoed question name (CK + A-padding for "*") is never mistaken for a hostname.
func parseNetBIOSNodeStatus(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	off := 12

	skipRR := func(count int, withTTL bool) bool {
		for i := 0; i < count; i++ {
			_, next, err := readName(msg, off)
			if err != nil {
				return false
			}
			off = next
			need := 4 // type + class
			if withTTL {
				need += 6 // TTL + rdlength
			}
			if off+need > len(msg) {
				return false
			}
			if withTTL {
				rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
				off += 10
				if rdlen < 0 || off+rdlen > len(msg) {
					return false
				}
				off += rdlen
			} else {
				off += 4
			}
		}
		return true
	}

	if !skipRR(qd, false) {
		return ""
	}

	best := ""
	bestRank := -1
	considerRDATA := func(rdata []byte) {
		if len(rdata) < 1 {
			return
		}
		numNames := int(rdata[0])
		pos := 1
		for i := 0; i < numNames; i++ {
			if pos+18 > len(rdata) {
				return
			}
			nameBytes := rdata[pos : pos+15]
			suffix := rdata[pos+15]
			flags := binary.BigEndian.Uint16(rdata[pos+16 : pos+18])
			pos += 18

			// Group names (WORKGROUP, MSBROWSE, …) are not hostnames.
			if flags&0x8000 != 0 {
				continue
			}
			rank := netBIOSSuffixRank(suffix)
			if rank < 0 {
				continue
			}
			trimmed := strings.TrimRight(string(nameBytes), " \x00")
			sanitized := SanitizeHostname(trimmed)
			if sanitized == "" || !isNetBIOSStyleName(sanitized) {
				continue
			}
			if rank > bestRank || (rank == bestRank && best == "") {
				best = sanitized
				bestRank = rank
			}
		}
	}

	parseAnswers := func(count int) bool {
		for i := 0; i < count; i++ {
			_, next, err := readName(msg, off)
			if err != nil {
				return false
			}
			off = next
			if off+10 > len(msg) {
				return false
			}
			rrType := binary.BigEndian.Uint16(msg[off : off+2])
			rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
			off += 10
			if rdlen < 0 || off+rdlen > len(msg) {
				return false
			}
			rdata := msg[off : off+rdlen]
			off += rdlen
			if rrType == 0x0021 { // NBSTAT
				considerRDATA(rdata)
			}
		}
		return true
	}

	if !parseAnswers(an) {
		return ""
	}
	// Authority is unused for NBSTAT; skip. Additional sometimes repeats answers.
	if !skipRR(ns, true) {
		return best
	}
	_ = parseAnswers(ar)
	return best
}

func netBIOSSuffixRank(suffix byte) int {
	// Prefer unique workstation, then file server, then messenger / domain roles.
	switch suffix {
	case 0x00:
		return 4
	case 0x20:
		return 3
	case 0x03:
		return 2
	case 0x1b, 0x1d, 0x1e:
		return 1
	default:
		return -1
	}
}

func isNetBIOSStyleName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	// Reject question-section padding / monotonous garbage (e.g. AAAAAAAAAAAAAAA).
	if isMonotoneASCII(name) {
		return false
	}
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func isMonotoneASCII(name string) bool {
	if len(name) < 3 {
		return false
	}
	first := name[0]
	for i := 1; i < len(name); i++ {
		if name[i] != first {
			return false
		}
	}
	return true
}

func queryChromecastName(ip string) string {
	client := &http.Client{Timeout: 100 * time.Millisecond}
	resp, err := client.Get("http://" + ip + ":8008/setup/eureka_info?params=name")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Name != "" {
			return data.Name
		}
	}
	return ""
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func fetchHTTPTitle(ip string) string {
	client := &http.Client{Timeout: 100 * time.Millisecond}
	resp, err := client.Get("http://" + ip)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err == nil {
			matches := titleRegex.FindSubmatch(body)
			if len(matches) >= 2 {
				title := strings.TrimSpace(string(matches[1]))
				if title != "" && len(title) < 50 && !strings.Contains(strings.ToLower(title), "404") && !strings.Contains(strings.ToLower(title), "index of") {
					return title
				}
			}
		}
	}
	return ""
}

func inferServices(hostname, vendor string) []string {
	var services []string
	hostLower := strings.ToLower(hostname)
	vendorLower := strings.ToLower(vendor)

	if strings.Contains(hostLower, "airplay") || strings.Contains(vendorLower, "apple") || strings.Contains(hostLower, "macbook") || strings.Contains(hostLower, "imac") || strings.Contains(hostLower, "iphone") || strings.Contains(hostLower, "ipad") {
		services = append(services, "AirPlay")
	}
	if strings.Contains(hostLower, "chromecast") || strings.Contains(hostLower, "google") {
		services = append(services, "Google Cast")
	}
	if strings.Contains(hostLower, "printer") || strings.Contains(vendorLower, "hp") || strings.Contains(vendorLower, "canon") || strings.Contains(vendorLower, "epson") || strings.Contains(vendorLower, "brother") {
		services = append(services, "Printer")
	}
	if strings.Contains(hostLower, "nas") || strings.Contains(vendorLower, "synology") || strings.Contains(vendorLower, "qnap") {
		services = append(services, "File Share (SMB)")
	}
	if strings.Contains(vendorLower, "sonos") {
		services = append(services, "Sonos Audio")
	}
	if strings.Contains(vendorLower, "hue") || strings.Contains(vendorLower, "philips") {
		services = append(services, "Philips Hue Link")
	}

	return services
}

func classifyDevice(hostname, vendor string, services []string, mac string) (devType, icon, model string) {
	hostLower := strings.ToLower(hostname)
	vendorLower := strings.ToLower(vendor)

	for _, s := range services {
		if s == "Printer" {
			return "Printer", "printer", "Network Printer"
		}
		if s == "iOS Wireless Sync" {
			return "Mobile Phone", "smartphone", "Apple iPhone / iPad"
		}
	}

	if strings.Contains(vendorLower, "sonos") {
		return "Smart Speaker", "speaker", "Sonos Audio Player"
	}
	if strings.Contains(hostLower, "homepod") {
		return "Smart Speaker", "speaker", "Apple HomePod"
	}

	if strings.Contains(hostLower, "apple-tv") || strings.Contains(hostLower, "appletv") {
		return "Smart TV", "tv", "Apple TV"
	}
	if strings.Contains(vendorLower, "roku") || strings.Contains(hostLower, "roku") {
		return "Smart TV", "tv", "Roku Streaming Device"
	}
	if strings.Contains(vendorLower, "chromecast") || strings.Contains(hostLower, "chromecast") {
		return "Smart TV", "tv", "Google Chromecast"
	}
	if strings.Contains(vendorLower, "sony") && (strings.Contains(hostLower, "bravia") || strings.Contains(hostLower, "tv")) {
		return "Smart TV", "tv", "Sony Smart TV"
	}
	if strings.Contains(vendorLower, "lg") && strings.Contains(hostLower, "tv") {
		return "Smart TV", "tv", "LG Smart TV"
	}

	if strings.Contains(vendorLower, "nintendo") || strings.Contains(hostLower, "switch") {
		return "Game Console", "gamepad", "Nintendo Switch"
	}
	if strings.Contains(vendorLower, "sony") && (strings.Contains(hostLower, "playstation") || strings.Contains(hostLower, "ps4") || strings.Contains(hostLower, "ps5")) {
		return "Game Console", "gamepad", "PlayStation Console"
	}
	if strings.Contains(vendorLower, "microsoft") && strings.Contains(hostLower, "xbox") {
		return "Game Console", "gamepad", "Xbox Console"
	}

	if strings.Contains(hostLower, "macbook") || strings.Contains(hostLower, "imac") || strings.Contains(hostLower, "mac-mini") || strings.Contains(hostLower, "mac-studio") || strings.Contains(hostLower, "macpro") || strings.Contains(hostLower, "laptop") || strings.Contains(hostLower, "mbp") || strings.HasSuffix(hostLower, "-pro") {
		return "Computer", "laptop", "Apple Mac"
	}
	if strings.Contains(vendorLower, "apple") {
		if strings.Contains(hostLower, "iphone") {
			return "Mobile Phone", "smartphone", "Apple iPhone"
		}
		if strings.Contains(hostLower, "ipad") {
			return "Tablet", "tablet", "Apple iPad"
		}
		if strings.Contains(hostLower, "watch") {
			return "Smartwatch", "watch", "Apple Watch"
		}
		return "Apple Device", "laptop", "Apple Device"
	}

	if strings.Contains(vendorLower, "raspberry pi") {
		return "SBC / Server", "cpu", "Raspberry Pi"
	}

	if strings.Contains(vendorLower, "espressif") || strings.Contains(vendorLower, "tuya") || strings.Contains(vendorLower, "hue") {
		return "Smart Home / IoT", "iot", "Smart IoT Accessory"
	}

	if strings.Contains(vendorLower, "ubiquiti") || strings.Contains(vendorLower, "tp-link") || strings.Contains(vendorLower, "netgear") || strings.Contains(vendorLower, "cisco") {
		if strings.Contains(hostLower, "ap") || strings.Contains(hostLower, "wifi") || strings.Contains(hostLower, "router") {
			return "Network Gear", "router", vendor + " Router / AP"
		}
	}

	if hostname != "" {
		return "Network Device", "device", hostname
	}

	return "Generic Device", "device", vendor
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range input {
		if _, value := keys[entry]; !value && entry != "" {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
