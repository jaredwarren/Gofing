package probes

import (
	"context"
	"sync"
	"time"
)

// ProbeDevice runs UPnP, NetBIOS, TLS, and Roku probes concurrently.
// Budget is capped at 1500ms so background enrichment stays bounded.
func ProbeDevice(ctx context.Context, ip string, knownPorts []int) ProbeResult {
	res := ProbeResult{IP: ip}
	if ip == "" {
		return res
	}

	pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		if upnp, err := probeUPnP(pctx, ip); err == nil && upnp != nil {
			mu.Lock()
			res.UPnP = upnp
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if nb, err := probeNetBIOS(pctx, ip); err == nil && nb != nil {
			mu.Lock()
			res.NetBIOS = nb
			mu.Unlock()
		}
	}()

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
		if tlsInfo, err := probeTLS(pctx, ip, tlsCandidates); err == nil && tlsInfo != nil {
			mu.Lock()
			res.TLS = tlsInfo
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if roku, err := probeRoku(pctx, ip); err == nil && roku != nil {
			mu.Lock()
			res.Roku = roku
			mu.Unlock()
		}
	}()

	wg.Wait()
	return res
}
