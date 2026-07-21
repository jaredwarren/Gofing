package mdns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// NameCandidate is one hostname observed during a deep lookup.
type NameCandidate struct {
	Hostname string `json:"hostname"`
	Source   string `json:"source"`
}

// LookupResult is the best hostname found for an IP, plus all candidates.
type LookupResult struct {
	Hostname   string          `json:"hostname,omitempty"`
	NameSource string          `json:"name_source,omitempty"`
	Candidates []NameCandidate `json:"candidates,omitempty"`
}

type cachedName struct {
	Hostname string
	Source   string
}

func (r *Resolver) rememberIPName(ip, hostname, source string) {
	hostname = SanitizeHostname(hostname)
	if hostname == "" || ip == "" {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	prev := r.ipNames[ip]
	name, src := PreferHostname(prev.Hostname, prev.Source, hostname, source)
	r.ipNames[ip] = cachedName{Hostname: name, Source: src}
}

func (r *Resolver) cachedForIP(ip string) cachedName {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.ipNames[ip]
}

// LookupHostnameDeep aggressively resolves a Bonjour/DNS name for ip.
// Intended for on-demand "Resolve name" actions (longer timeouts + retries).
func (r *Resolver) LookupHostnameDeep(ip string) LookupResult {
	var candidates []NameCandidate
	bestName, bestSrc := "", NameSourceNone

	consider := func(name, source string) {
		name = SanitizeHostname(name)
		if name == "" {
			return
		}
		candidates = append(candidates, NameCandidate{Hostname: name, Source: source})
		bestName, bestSrc = PreferHostname(bestName, bestSrc, name, source)
	}

	if c := r.cachedForIP(ip); c.Hostname != "" {
		consider(c.Hostname, c.Source)
	}

	if h := reverseDNSWithTimeout(ip, 2*time.Second); h != "" {
		consider(h, NameSourceDNS)
	}
	// Dedicated mDNS PTR with a long wait; dns-sd is asynchronous.
	if h := mdnsReversePTR(ip, 3500*time.Millisecond); h != "" {
		consider(h, NameSourceDNS)
	} else if h := mdnsReversePTR(ip, 3500*time.Millisecond); h != "" {
		consider(h, NameSourceDNS)
	}

	if bestName != "" {
		r.rememberIPName(ip, bestName, bestSrc)
	}

	return LookupResult{
		Hostname:   bestName,
		NameSource: bestSrc,
		Candidates: dedupeCandidates(candidates),
	}
}

// LookupHostnameQuick is used during scans: cache + moderate reverse DNS/mDNS.
func (r *Resolver) LookupHostnameQuick(ip string) (hostname, source string) {
	if c := r.cachedForIP(ip); c.Hostname != "" {
		return c.Hostname, c.Source
	}
	if h := reverseDNSWithTimeout(ip, 1200*time.Millisecond); h != "" {
		r.rememberIPName(ip, h, NameSourceDNS)
		return h, NameSourceDNS
	}
	return "", NameSourceNone
}

func reverseDNSWithTimeout(ip string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Split budget: unicast first, then mDNS PTR with remaining time (min 400ms).
	unicastBudget := timeout / 2
	if unicastBudget > 900*time.Millisecond {
		unicastBudget = 900 * time.Millisecond
	}
	if unicastBudget < 300*time.Millisecond {
		unicastBudget = timeout / 3
	}

	uCtx, uCancel := context.WithTimeout(ctx, unicastBudget)
	names, err := net.DefaultResolver.LookupAddr(uCtx, ip)
	uCancel()
	if err == nil && len(names) > 0 {
		if clean := normalizeResolvedName(names[0]); clean != "" {
			return clean
		}
	}

	deadline, ok := ctx.Deadline()
	remaining := timeout / 2
	if ok {
		remaining = time.Until(deadline)
	}
	if remaining < 400*time.Millisecond {
		remaining = 400 * time.Millisecond
	}
	if name := mdnsReversePTR(ip, remaining); name != "" {
		return name
	}
	return ""
}

func mdnsReversePTR(ip string, timeout time.Duration) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	parsed = parsed.To4()
	if parsed == nil {
		return ""
	}
	ptr := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", parsed[3], parsed[2], parsed[1], parsed[0])

	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dns-sd", "-q", ptr, "PTR")
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()

	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Fields(line)
		hasPTR := false
		for _, f := range fields {
			if f == "PTR" {
				hasPTR = true
				break
			}
		}
		if !hasPTR || len(fields) == 0 {
			continue
		}
		candidate := strings.TrimSuffix(fields[len(fields)-1], ".")
		if !strings.Contains(candidate, ".") {
			continue
		}
		if clean := normalizeResolvedName(candidate); clean != "" {
			return clean
		}
	}
	return ""
}

func dedupeCandidates(in []NameCandidate) []NameCandidate {
	seen := make(map[string]bool)
	var out []NameCandidate
	for _, c := range in {
		key := strings.ToLower(c.Hostname) + "|" + c.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}
