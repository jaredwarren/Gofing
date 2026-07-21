package mdns

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Service types that commonly advertise a usable hostname on home LANs.
var browseServiceTypes = []string{
	"_companion-link._tcp",
	"_airplay._tcp",
	"_raop._tcp",
	"_device-info._tcp",
	"_rdlink._tcp",
	"_hap._tcp",
	"_homekit._tcp",
	"_googlecast._tcp",
	"_smb._tcp",
	"_ipp._tcp",
	"_printer._tcp",
	"_ssh._tcp",
	"_workstation._tcp",
	"_http._tcp",
}

var (
	reachedAtHostRe = regexp.MustCompile(`(?i)can be reached at\s+([^\s:]+)`)
	reachedAtIPRe   = regexp.MustCompile(`(?i)can be reached at\s+(\d+\.\d+\.\d+\.\d+)`)
)

func (r *Resolver) backgroundDiscovery() {
	r.runBrowsePass(3 * time.Second)
	ticker := time.NewTicker(90 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.runBrowsePass(5 * time.Second)
	}
}

func (r *Resolver) runBrowsePass(browseTimeout time.Duration) {
	const maxResolves = 24
	resolved := 0
	for _, serviceType := range browseServiceTypes {
		if resolved >= maxResolves {
			return
		}
		for _, instance := range r.browseServiceInstances(serviceType, browseTimeout) {
			if resolved >= maxResolves {
				return
			}
			host, hints := lookupServiceDetails(instance, serviceType, 1500*time.Millisecond)
			if host == "" {
				continue
			}
			ip := lookupHostnameIPv4(host, 1500*time.Millisecond)
			if ip == "" {
				continue
			}
			r.rememberIPName(ip, host, NameSourceARP)
			if hints.Model != "" || hints.DeviceType != "" || len(hints.Services) > 0 {
				r.rememberIPHints(ip, hints)
			}
			resolved++
		}
	}
}

func (r *Resolver) browseServiceInstances(serviceType string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dns-sd", "-B", serviceType, "local")
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	seen := make(map[string]bool)
	var instances []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		addIdx := -1
		for i, f := range fields {
			if f == "Add" {
				addIdx = i
				break
			}
		}
		if addIdx < 0 || len(fields) < addIdx+5 {
			continue
		}
		// dns-sd -B columns: TIMESTAMP Add Flags If Domain ServiceType Instance...
		instance := strings.Join(fields[addIdx+4:], " ")
		instance = strings.TrimSpace(instance)
		if instance == "" || strings.HasPrefix(instance, "DNSService") {
			continue
		}
		key := strings.ToLower(instance)
		if seen[key] {
			continue
		}
		seen[key] = true
		instances = append(instances, instance)

		r.cacheMu.Lock()
		r.mdnsCache[key] = instance
		r.cacheMu.Unlock()
	}
	return instances
}

func lookupServiceHostname(instance, serviceType string, timeout time.Duration) string {
	host, _ := lookupServiceDetails(instance, serviceType, timeout)
	return host
}

func lookupServiceDetails(instance, serviceType string, timeout time.Duration) (hostname string, hints FingerprintHints) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dns-sd", "-L", instance, serviceType, "local")
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	host, txt := parseDNSSDLookupOutput(out.String())
	hints = hintsFromTXT(serviceType, txt)
	return host, hints
}

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

func lookupHostnameIPv4(hostname string, timeout time.Duration) string {
	if hostname == "" {
		return ""
	}
	query := hostname
	if !strings.Contains(query, ".") {
		query = query + ".local"
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dns-sd", "-G", "v4", query)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	for _, line := range strings.Split(out.String(), "\n") {
		m := reachedAtIPRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		ip := m[1]
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// Parse helpers exported for tests via package-level functions below.

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
