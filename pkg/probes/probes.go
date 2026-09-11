package probes

import (
	"context"
	"sync"
	"time"
)

// ProbeDevice runs UPnP, NetBIOS, and TLS certificate probes concurrently against the given IP.
// A maximum budget of 1500ms is enforced to ensure background discovery remains fast and bounded.
func ProbeDevice(ctx context.Context, ip string, knownPorts []int) ProbeResult {
	res := ProbeResult{IP: ip}
	if ip == "" {
		return res
	}

	pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. UPnP / SSDP probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		if upnp, err := ProbeUPnP(pctx, ip); err == nil && upnp != nil {
			mu.Lock()
			res.UPnP = upnp
			mu.Unlock()
		}
	}()

	// 2. NetBIOS NBNS probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		if nb, err := ProbeNetBIOS(pctx, ip); err == nil && nb != nil {
			mu.Lock()
			res.NetBIOS = nb
			mu.Unlock()
		}
	}()

	// 3. TLS Certificate probe (filtering candidate HTTPS ports from knownPorts if available)
	var tlsCandidates []int
	for _, p := range knownPorts {
		if p == 443 || p == 8443 || p == 5001 || p == 8006 || p == 9443 || p == 4443 {
			tlsCandidates = append(tlsCandidates, p)
		}
	}
	if len(tlsCandidates) == 0 {
		tlsCandidates = []int{443, 8443}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if tlsInfo, err := ProbeTLS(pctx, ip, tlsCandidates); err == nil && tlsInfo != nil {
			mu.Lock()
			res.TLS = tlsInfo
			mu.Unlock()
		}
	}()

	// 4. Roku ECP — one unauthenticated GET for the owner-assigned name.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if roku, err := ProbeRoku(pctx, ip); err == nil && roku != nil {
			mu.Lock()
			res.Roku = roku
			mu.Unlock()
		}
	}()

	wg.Wait()
	return res
}
