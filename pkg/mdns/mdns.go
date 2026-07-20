package mdns

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DeviceDetails contains resolved hostnames, friendly names, and inferred device types.
type DeviceDetails struct {
	Hostname   string   `json:"hostname"`
	DeviceType string   `json:"device_type"`
	Icon       string   `json:"icon"`
	Model      string   `json:"model"`
	Services   []string `json:"services"`
}

// Resolver handles hostname resolution and mDNS fingerprinting.
type Resolver struct{}

// New returns a new Resolver.
func New() *Resolver {
	return &Resolver{}
}

// ResolveDevice performs hostname reverse lookup, NetBIOS query, HTTP title grab, and service classification.
func (r *Resolver) ResolveDevice(ip string, mac string, vendor string, isGateway bool, hostComputerName string) DeviceDetails {
	if isGateway {
		return DeviceDetails{
			Hostname:   "Default Gateway / Router (" + vendor + ")",
			DeviceType: "Router",
			Icon:       "router",
			Model:      vendor + " Gateway",
			Services:   []string{"Gateway", "DNS", "DHCP"},
		}
	}

	hostname := ""

	// 1. Check if this is the host Mac running Gofing
	if hostComputerName != "" {
		hostname = hostComputerName
	}

	// 2. Reverse DNS lookup with strict 150ms timeout
	if hostname == "" {
		hostname = reverseDNS(ip)
	}

	// 3. Try NetBIOS Name Query (UDP 137)
	if hostname == "" || hostname == ip {
		if netbiosName := queryNetBIOSName(ip); netbiosName != "" {
			hostname = netbiosName
		}
	}

	// 4. Try Chromecast / Google Nest setup API (http://<ip>:8008/setup/eureka_info)
	if hostname == "" || hostname == ip {
		if ccName := queryChromecastName(ip); ccName != "" {
			hostname = ccName
		}
	}

	// 5. Try HTTP Title Grabber (http://<ip>:80 or 8080) for web servers/routers/NAS
	if hostname == "" || hostname == ip {
		if title := fetchHTTPTitle(ip); title != "" {
			hostname = title
		}
	}

	// 6. Infer services from hostname & vendor
	services := inferServices(hostname, vendor)

	// 7. Classify device type, icon, and model
	devType, icon, model := classifyDevice(hostname, vendor, services, mac)

	return DeviceDetails{
		Hostname:   hostname,
		DeviceType: devType,
		Icon:       icon,
		Model:      model,
		Services:   services,
	}
}

func reverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		if name != "" {
			return name
		}
	}

	return ""
}

func queryNetBIOSName(ip string) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), 100*time.Millisecond)
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

	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Write(req)
	if err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 72 {
		return ""
	}

	nameBytes := buf[57:72]
	name := strings.TrimSpace(string(nameBytes))
	return name
}

func queryChromecastName(ip string) string {
	client := &http.Client{Timeout: 150 * time.Millisecond}
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
	client := &http.Client{Timeout: 150 * time.Millisecond}
	resp, err := client.Get("http://" + ip)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
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

	if strings.Contains(hostLower, "airplay") || strings.Contains(vendorLower, "apple") || strings.Contains(hostLower, "macbook") || strings.Contains(hostLower, "imac") {
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

	if strings.Contains(hostLower, "macbook") || strings.Contains(hostLower, "imac") || strings.Contains(hostLower, "mac-mini") || strings.Contains(hostLower, "mac-studio") || strings.Contains(hostLower, "macpro") || strings.Contains(hostLower, "laptop") {
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
