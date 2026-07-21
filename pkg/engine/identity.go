package engine

import (
	"strconv"
	"strings"
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

// DeviceID returns a stable device identity. Prefer MAC; fall back to ip:<ipv4>.
func DeviceID(mac, ip string) string {
	if n := NormalizeMAC(mac); n != "" && looksLikeMAC(n) {
		return n
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
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
