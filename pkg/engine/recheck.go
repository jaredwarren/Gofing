package engine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RecheckResult reports what an on-demand presence check found, including which
// signal decided it — the useful part when a user is asking "is this thing
// really offline?".
type RecheckResult struct {
	Device    Device  `json:"device"`
	WasOnline bool    `json:"was_online"`
	IsOnline  bool    `json:"is_online"`
	Changed   bool    `json:"changed"`
	Evidence  string  `json:"evidence"` // arp | probe | none
	LatencyMs float64 `json:"latency_ms,omitempty"`
	Message   string  `json:"message"`
}

// RecheckDevice re-evaluates one device's presence immediately, bypassing the
// presence tier's cadence and its damping.
//
// It applies the same rule the presence tier does — a resolved ARP entry is
// proof of presence, an active probe is a fallback — but uses the patient probe
// and a fresh ARP read, because a person is waiting for the answer and can
// afford a second or two. Evidence is reported so the result is explicable
// rather than just a flipped dot.
func (e *Engine) RecheckDevice(ctx context.Context, id string) (RecheckResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dev, ok := e.GetDevice(id)
	if !ok {
		return RecheckResult{}, fmt.Errorf("device not found")
	}
	if dev.IP == "" {
		return RecheckResult{Device: dev, WasOnline: dev.IsOnline, IsOnline: dev.IsOnline,
			Evidence: "none", Message: "device has no IP address to check"}, nil
	}

	netInfo := e.currentNetInfo(30 * time.Second)
	subnet, iface := "", ""
	if netInfo != nil {
		subnet = netInfo.SubnetCIDR
		iface = strings.TrimSpace(netInfo.InterfaceName)
	}

	// Probe first: besides answering directly, it provokes the ARP resolution
	// that the read below depends on.
	lat, probeOK := e.probeIPVerify(ctx, dev.IP)

	normMAC := NormalizeMAC(dev.MAC)
	arpOK, arpIP := false, ""
	for _, row := range e.readARPFresh(ctx) {
		if row.MAC == "" {
			continue
		}
		if subnet != "" && !ipInCIDR(row.IP, subnet) {
			continue
		}
		if iface != "" && row.Iface != "" && !strings.EqualFold(row.Iface, iface) {
			continue
		}
		rowMAC := NormalizeMAC(row.MAC)
		if normMAC != "" && rowMAC == normMAC {
			arpOK, arpIP = true, row.IP
			break
		}
		if normMAC == "" && row.IP == dev.IP {
			arpOK, arpIP = true, row.IP
			break
		}
	}

	var res RecheckResult
	switch {
	case arpOK:
		res.Evidence = "arp"
	case probeOK:
		res.Evidence = "probe"
	default:
		res.Evidence = "none"
	}
	online := arpOK || probeOK

	now := time.Now()
	var out Device
	e.mu.Lock()
	d, still := e.devices[id]
	if !still {
		e.mu.Unlock()
		return RecheckResult{}, fmt.Errorf("device not found")
	}
	before := *d
	if online {
		e.setOnlineLocked(d, true)
		d.LastSeen = now
		if lat > 0 {
			d.LatencyMs = lat
		}
		// A device found at a new address has moved; follow it.
		if arpIP != "" && arpIP != d.IP {
			d.IP = arpIP
		}
		e.missCount[id] = 0
		delete(e.verifyMiss, id)
	} else {
		// A single failed check is not grounds for retiring a device — that is
		// the presence tier's debounced job. Record the miss and let it decide.
		e.missCount[id]++
		if e.missCount[id] >= offlineMissThreshold && d.IsOnline {
			e.setOnlineLocked(d, false)
		}
	}
	out = *d
	e.mu.Unlock()

	res.Device = out
	res.WasOnline = before.IsOnline
	res.IsOnline = out.IsOnline
	res.Changed = deviceChangedMeaningfully(before, out)
	res.LatencyMs = lat

	switch {
	case arpOK && !probeOK:
		res.Message = "Online — answered ARP at Layer 2 but ignores ping, which is normal for consoles, printers and sleeping phones."
	case arpOK && probeOK:
		res.Message = fmt.Sprintf("Online — replied to a probe in %.0f ms.", lat)
	case probeOK:
		res.Message = fmt.Sprintf("Online — replied to a probe in %.0f ms, but has no ARP entry.", lat)
	case out.IsOnline:
		res.Message = fmt.Sprintf("No response. Still shown online pending %d consecutive misses.", offlineMissThreshold)
	default:
		res.Message = "No response to ARP or an active probe — appears genuinely offline."
	}

	e.persistDevice(out)
	if res.Changed {
		e.emitEvent("device_updated", &out)
	}
	return res, nil
}
