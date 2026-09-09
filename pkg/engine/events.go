package engine

import (
	"math"

	"github.com/jaredwarren/Gofing/pkg/ports"
)

// deviceChangedMeaningfully reports whether a UI-visible field differs between
// two snapshots of a device.
//
// The presence tier revisits every known device every few seconds, and almost
// every visit changes LastSeen and jitters LatencyMs without changing anything
// a viewer would notice. Emitting on those made the browser re-render the whole
// table several times a second. Bookkeeping-only fields are likewise ignored.
//
// Err on the side of reporting a change: a false positive costs one extra SSE
// frame, a false negative leaves the UI stale.
func deviceChangedMeaningfully(before, after Device) bool {
	if before.IsOnline != after.IsOnline ||
		before.IP != after.IP ||
		before.MAC != after.MAC ||
		before.Hostname != after.Hostname ||
		before.NameSource != after.NameSource ||
		before.CustomName != after.CustomName ||
		before.Note != after.Note ||
		before.DeviceType != after.DeviceType ||
		before.DeviceTypeOverride != after.DeviceTypeOverride ||
		before.Icon != after.Icon ||
		before.Model != after.Model ||
		before.Vendor != after.Vendor ||
		before.IsPrivateMAC != after.IsPrivateMAC ||
		before.RiskScore != after.RiskScore {
		return true
	}
	if !sameStrings(before.Services, after.Services) ||
		!sameStrings(before.RiskFindings, after.RiskFindings) ||
		!sameStrings(before.PreviousMACs, after.PreviousMACs) {
		return true
	}
	if !samePorts(before.OpenPorts, after.OpenPorts) {
		return true
	}
	return latencyDrifted(before.LatencyMs, after.LatencyMs)
}

// latencyDrifted reports whether a round-trip time changed enough to be worth
// telling the UI about. Normal Wi-Fi jitter is not.
func latencyDrifted(a, b float64) bool {
	delta := math.Abs(a - b)
	if delta <= 5 {
		return false
	}
	return delta > 0.25*math.Max(math.Max(a, b), 1)
}

// samePorts reports whether two open-port lists hold the same entries in order.
func samePorts(a, b []ports.ServicePort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
