package mdns

import (
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

// Resolver handles hostname resolution and multi-layer device fingerprinting.
type Resolver struct {
	mdnsCache   map[string]string           // service instance names
	ipNames     map[string]cachedName       // IP → best Bonjour/DNS name
	ipHints     map[string]FingerprintHints // IP → TXT-derived model/type
	cacheMu     sync.RWMutex
}

// New returns a new Resolver instance and starts background mDNS discovery.
func New() *Resolver {
	r := &Resolver{
		mdnsCache: make(map[string]string),
		ipNames:   make(map[string]cachedName),
		ipHints:   make(map[string]FingerprintHints),
	}
	go r.backgroundDiscovery()
	return r
}

// ResolveDevice performs multi-layer non-blocking fingerprinting.
// arpHostname is an optional name from macOS `arp -a` (Bonjour cache).
func (r *Resolver) ResolveDevice(ip string, mac string, vendor string, isGateway bool, hostComputerName string, arpHostname string) DeviceDetails {
	if isGateway {
		return DeviceDetails{
			Hostname:   "Network Gateway",
			NameSource: NameSourceHost,
			DeviceType: "Router",
			Icon:       "router",
			Model:      vendor + " Gateway",
			Services:   []string{"Gateway", "DNS", "DHCP"},
		}
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

	// iOS probe contributes type/vendor hints only (not hostname)
	isIOS := probeIOSSyncPort(ip)
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

	// Priority 3: Reverse DNS / dns-sd PTR (moderate timeout during scans)
	if hostname == "" {
		if h, src := r.LookupHostnameQuick(ip); h != "" {
			hostname = h
			nameSource = src
		}
	}

	// Priority 4: Google Cast / Nest API
	if ccName := SanitizeHostname(queryChromecastName(ip)); ccName != "" {
		services = append(services, "Google Cast")
		if hostname == "" {
			hostname = ccName
			nameSource = NameSourceCast
		}
		if detectedType == "" {
			detectedType = "Smart TV"
			detectedIcon = "tv"
			detectedModel = "Google Nest / Chromecast"
		}
	}

	// Priority 5: HTTP Title Grabber
	if hostname == "" {
		if title := SanitizeHostname(fetchHTTPTitle(ip)); title != "" {
			hostname = title
			nameSource = NameSourceHTTP
		}
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
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "62078"), 40*time.Millisecond)
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
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), 80*time.Millisecond)
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

	// NBNS node status replies encode names as 15-byte space-padded ASCII fields.
	// Scan the payload for the first plausible unique workstation name (suffix 0x00).
	payload := buf[:n]
	for i := 0; i+16 <= len(payload); i++ {
		nameBytes := payload[i : i+15]
		suffix := payload[i+15]
		// Common NetBIOS name types: workstation/file server/messenger/domain
		switch suffix {
		case 0x00, 0x03, 0x20, 0x1b, 0x1d, 0x1e:
		default:
			continue
		}
		trimmed := strings.TrimRight(string(nameBytes), " \x00")
		if sanitized := SanitizeHostname(trimmed); sanitized != "" && isNetBIOSStyleName(sanitized) {
			return sanitized
		}
	}
	return ""
}

func isNetBIOSStyleName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
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
