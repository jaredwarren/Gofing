package dhcp

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	macRe = regexp.MustCompile(`(?i)^[0-9a-f]{1,2}([:\-])[0-9a-f]{1,2}(?:[:\-][0-9a-f]{1,2}){4}$`)
	ipRe  = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
)

// Parse accepts JSON leases, CSV rows, or a TP-Link-style client list
// (Device Name / MAC / IP / Lease Time as 4-line groups).
func Parse(data []byte) []Lease {
	text := strings.TrimSpace(string(data))
	text = strings.TrimPrefix(text, "\ufeff")
	if text == "" {
		return nil
	}

	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		if leases, ok := parseJSON(trimmed); ok {
			return leases
		}
	}

	if leases := parseCSV(text); len(leases) > 0 {
		return leases
	}
	return parseClientList(text)
}

type jsonLease struct {
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
}

func parseJSON(text string) ([]Lease, bool) {
	var rows []jsonLease
	if err := json.Unmarshal([]byte(text), &rows); err == nil {
		return normalizeJSON(rows), true
	}
	var wrapped struct {
		Leases  []jsonLease `json:"leases"`
		Clients []jsonLease `json:"clients"`
		Devices []jsonLease `json:"devices"`
	}
	if err := json.Unmarshal([]byte(text), &wrapped); err != nil {
		return nil, false
	}
	rows = wrapped.Leases
	if len(rows) == 0 {
		rows = wrapped.Clients
	}
	if len(rows) == 0 {
		rows = wrapped.Devices
	}
	if len(rows) == 0 {
		return nil, false
	}
	return normalizeJSON(rows), true
}

func normalizeJSON(rows []jsonLease) []Lease {
	var out []Lease
	for _, r := range rows {
		name := strings.TrimSpace(r.Hostname)
		if name == "" {
			name = strings.TrimSpace(r.Name)
		}
		out = appendLease(out, name, r.MAC, r.IP)
	}
	return out
}

func parseCSV(text string) []Lease {
	var out []Lease
	matched := 0
	for _, line := range splitLines(text) {
		if isHeader(line) {
			continue
		}
		if !strings.Contains(line, ",") {
			continue
		}
		parts := splitCSV(line)
		if len(parts) < 3 {
			continue
		}
		name, mac, ip := "", "", ""
		for _, p := range parts {
			switch {
			case looksLikeMAC(p) && mac == "":
				mac = p
			case looksLikeIP(p) && ip == "":
				ip = p
			case name == "" && !looksLikeMAC(p) && !looksLikeIP(p):
				name = p
			}
		}
		if mac == "" || ip == "" {
			continue
		}
		matched++
		out = appendLease(out, name, mac, ip)
	}
	if matched == 0 {
		return nil
	}
	return out
}

func parseClientList(text string) []Lease {
	var lines []string
	for _, line := range splitLines(text) {
		if isHeader(line) {
			continue
		}
		lines = append(lines, line)
	}

	var out []Lease
	seen := map[string]bool{}
	for i, line := range lines {
		if !looksLikeMAC(line) {
			continue
		}
		name := ""
		if i > 0 && !looksLikeMAC(lines[i-1]) && !looksLikeIP(lines[i-1]) {
			name = lines[i-1]
		}
		ip := ""
		if i+1 < len(lines) && looksLikeIP(lines[i+1]) {
			ip = lines[i+1]
		}
		l, ok := makeLease(name, line, ip)
		if !ok {
			continue
		}
		if seen[l.MAC] {
			continue
		}
		seen[l.MAC] = true
		out = append(out, l)
	}
	return out
}

func appendLease(out []Lease, name, mac, ip string) []Lease {
	l, ok := makeLease(name, mac, ip)
	if !ok {
		return out
	}
	return append(out, l)
}

func makeLease(name, mac, ip string) (Lease, bool) {
	name = strings.TrimSpace(name)
	if name == "" || name == "---" || name == "-" {
		return Lease{}, false
	}
	if !utf8.ValidString(name) {
		return Lease{}, false
	}
	mac = strings.TrimSpace(mac)
	if !looksLikeMAC(mac) {
		return Lease{}, false
	}
	ip = strings.TrimSpace(ip)
	if ip != "" && !looksLikeIP(ip) {
		ip = ""
	}
	return Lease{Hostname: name, MAC: mac, IP: ip}, true
}

func looksLikeMAC(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	normalized := strings.ReplaceAll(s, "-", ":")
	hw, err := net.ParseMAC(normalized)
	if err != nil {
		return false
	}
	return len(hw) == 6 && macRe.MatchString(s)
}

func looksLikeIP(s string) bool {
	s = strings.TrimSpace(s)
	if !ipRe.MatchString(s) {
		return false
	}
	return net.ParseIP(s) != nil && net.ParseIP(s).To4() != nil
}

func isHeader(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "device name") && strings.Contains(lower, "mac")
}

func splitLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func splitCSV(line string) []string {
	var parts []string
	for _, p := range strings.Split(line, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
