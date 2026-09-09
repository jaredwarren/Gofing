package engine

import "time"

// Enrichment TTLs. Identity — hostname, vendor, device type — is near-static;
// presence is not. Separating the two is what turns a fingerprint of every
// device every 30 seconds into a fingerprint of a handful of devices per hour.
//
// A device that is still missing information is retried far sooner than one
// that is fully identified, because for the former there is something to gain.
const (
	enrichTTLIdentified = 12 * time.Hour   // hostname, type and vendor all known
	enrichTTLPartial    = 1 * time.Hour    // named but untyped, or missing a vendor
	enrichTTLUnnamed    = 10 * time.Minute // no hostname at all — keep trying
	enrichFailBase      = 5 * time.Minute  // multiplied by 2^EnrichFailures
	enrichFailCap       = 12 * time.Hour
)

// EnrichReason explains why a device was queued for fingerprinting. It also
// determines queue priority: a device the user just asked about outranks one
// that merely aged past its TTL.
type EnrichReason string

const (
	EnrichReasonManual  EnrichReason = "manual"  // user asked directly
	EnrichReasonNew     EnrichReason = "new"     // never fingerprinted
	EnrichReasonWoke    EnrichReason = "woke"    // offline -> online transition
	EnrichReasonUnnamed EnrichReason = "unnamed" // still has no hostname
	EnrichReasonUntyped EnrichReason = "untyped" // still has no type or vendor
	EnrichReasonStale   EnrichReason = "stale"   // TTL elapsed
)

// priority returns the queue band for a reason: lower is served first.
func (r EnrichReason) priority() int {
	switch r {
	case EnrichReasonManual:
		return 0
	case EnrichReasonNew, EnrichReasonWoke, EnrichReasonUnnamed, EnrichReasonUntyped:
		return 1
	default:
		return 2
	}
}

// enrichBackoff returns how long to wait after EnrichFailures consecutive
// fruitless attempts. Without this, a DHCP row for a device that left the
// network months ago would be re-probed forever at the unnamed TTL.
func enrichBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	if failures > 32 {
		return enrichFailCap
	}
	backoff := enrichFailBase << uint(failures-1)
	if backoff > enrichFailCap || backoff <= 0 {
		return enrichFailCap
	}
	return backoff
}

// vendorKnown reports whether d has a vendor worth keeping. The OUI lookup
// returns these placeholders on a miss, and they should not count as identity.
func vendorKnown(vendor string) bool {
	switch vendor {
	case "", "Unknown Vendor", "Generic Device":
		return false
	default:
		return true
	}
}

// enrichTTL returns how long d's fingerprint stays fresh. identifiedTTL is the
// user-configured ceiling for a fully identified device.
func enrichTTL(d Device, identifiedTTL time.Duration) time.Duration {
	if identifiedTTL <= 0 {
		identifiedTTL = enrichTTLIdentified
	}
	switch {
	case d.Hostname == "" && d.CustomName == "":
		return enrichTTLUnnamed
	case d.DeviceType == "" || !vendorKnown(d.Vendor):
		return enrichTTLPartial
	default:
		return identifiedTTL
	}
}

// needsEnrichment decides whether d should be fingerprinted now, and why.
//
// It is deliberately pure: no locks, no I/O, no Engine receiver. Call it with a
// Device value so it can be exercised exhaustively in tests and called cheaply
// for every device on every tier pass.
func needsEnrichment(d Device, now time.Time, identifiedTTL time.Duration) (EnrichReason, bool) {
	if d.IP == "" {
		return "", false // nothing to probe
	}
	if d.LastEnrichedAt.IsZero() {
		return EnrichReasonNew, true
	}
	// Respect the failure backoff before considering any TTL.
	if backoff := enrichBackoff(d.EnrichFailures); backoff > 0 {
		if now.Before(d.LastEnrichedAt.Add(backoff)) {
			return "", false
		}
	}

	age := now.Sub(d.LastEnrichedAt)
	switch {
	case d.Hostname == "" && d.CustomName == "":
		return EnrichReasonUnnamed, age >= enrichTTLUnnamed
	case d.DeviceType == "" || !vendorKnown(d.Vendor):
		return EnrichReasonUntyped, age >= enrichTTLPartial
	default:
		if identifiedTTL <= 0 {
			identifiedTTL = enrichTTLIdentified
		}
		return EnrichReasonStale, age >= identifiedTTL
	}
}
