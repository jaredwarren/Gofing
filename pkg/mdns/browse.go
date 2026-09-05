package mdns

import (
	"net"
	"regexp"
	"strings"
)

var (
	reachedAtHostRe = regexp.MustCompile(`(?i)can be reached at\s+([^\s:]+)`)
	reachedAtIPRe   = regexp.MustCompile(`(?i)can be reached at\s+(\d+\.\d+\.\d+\.\d+)`)
)

func (r *Resolver) rememberIPHints(ip string, hints FingerprintHints) {
	if ip == "" {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.ipHints[ip] = mergeHints(r.ipHints[ip], hints)
}

func (r *Resolver) hintsForIP(ip string) FingerprintHints {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.ipHints[ip]
}

// parseBrowseAddInstance extracts the Bonjour instance name from a dns-sd -B line.
//
// Columns: TIMESTAMP Add Flags If Domain ServiceType Instance Name...
func parseBrowseAddInstance(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	addIdx := -1
	for i, f := range fields {
		if f == "Add" {
			addIdx = i
			break
		}
	}
	if addIdx < 0 || len(fields) < addIdx+6 {
		return ""
	}
	// Add, Flags, If, Domain, ServiceType, Instance...
	start := addIdx + 5
	if !strings.HasPrefix(fields[addIdx+4], "_") {
		start = addIdx + 4
	}
	instance := strings.TrimSpace(strings.Join(fields[start:], " "))
	if instance == "" || strings.HasPrefix(instance, "DNSService") {
		return ""
	}
	return instance
}

func parseReachedAtHost(line string) string {
	m := reachedAtHostRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return normalizeResolvedName(m[1])
}

func parseReachedAtIP(line string) string {
	m := reachedAtIPRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	if net.ParseIP(m[1]) == nil {
		return ""
	}
	return m[1]
}
