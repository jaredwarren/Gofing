package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/jaredwarren/Gofing/pkg/network"
)

// NormalizeMAC returns an uppercase colon-separated MAC, or "" if invalid/empty.
func NormalizeMAC(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}

	clean := strings.ToUpper(mac)
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, ".", "")
	clean = strings.ReplaceAll(clean, " ", "")

	if len(clean) != 12 {
		return strings.ToUpper(mac) // best-effort passthrough
	}
	for _, ch := range clean {
		if !isHex(ch) {
			return strings.ToUpper(mac)
		}
	}

	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = clean[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

func isHex(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')
}

// DeviceID returns a stable device identity within a network. Prefer MAC; fall back to ip:<ipv4>.
func DeviceID(mac, ip string) string {
	if n := NormalizeMAC(mac); n != "" && looksLikeMAC(n) {
		return n
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

// NetworkKeyFromInfo returns a stable key for the active LAN (SSID preferred, else gateway+subnet).
func NetworkKeyFromInfo(info *network.Info) string {
	if info == nil {
		return ""
	}
	ssid := strings.TrimSpace(info.SSID)
	lower := strings.ToLower(ssid)
	if ssid != "" && !strings.Contains(lower, "not associated") && !strings.Contains(lower, "error") {
		// Avoid "/" so ScopedDeviceID can use it as a separator.
		ssid = strings.ReplaceAll(ssid, "/", "_")
		return "ssid:" + ssid
	}
	if info.GatewayIP != "" && info.SubnetCIDR != "" {
		return "gw:" + info.GatewayIP + "@" + info.SubnetCIDR
	}
	if info.SubnetCIDR != "" {
		return "subnet:" + info.SubnetCIDR
	}
	return ""
}

// ScopedDeviceID namespaces a device ID by network so the same MAC on two Wi‑Fis
// does not collide or leak across inventory views.
func ScopedDeviceID(networkKey, mac, ip string) string {
	base := DeviceID(mac, ip)
	if base == "" {
		return ""
	}
	if networkKey == "" {
		return base
	}
	return networkKey + "/" + base
}

func stripNetworkScope(id string) string {
	if id == "" {
		return ""
	}
	i := strings.Index(id, "/")
	if i < 0 {
		return id
	}
	prefix := id[:i]
	if strings.HasPrefix(prefix, "ssid:") || strings.HasPrefix(prefix, "gw:") || strings.HasPrefix(prefix, "subnet:") {
		return id[i+1:]
	}
	return id
}

func looksLikeMAC(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, ch := range p {
			if !isHex(ch) {
				return false
			}
		}
	}
	return true
}

// IsPrivateMAC reports whether the MAC has the locally administered (U/L) bit set.
func IsPrivateMAC(mac string) bool {
	n := NormalizeMAC(mac)
	if !looksLikeMAC(n) {
		return false
	}
	first, err := strconv.ParseUint(n[0:2], 16, 8)
	if err != nil {
		return false
	}
	return first&0x02 != 0
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
