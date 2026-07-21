package mdns

// Hostname source identifiers (persisted on Device.NameSource).
// Higher rank wins and is sticky against lower-ranked scans.
const (
	NameSourceNone = ""
	NameSourceHost = "host" // this Mac's computer name
	NameSourceARP  = "arp"  // macOS arp -a / Bonjour cache
	NameSourceDNS  = "dns"  // reverse DNS or dns-sd PTR
	NameSourceCast = "cast" // Chromecast / Nest eureka name
	NameSourceHTTP = "http" // HTTP <title>
)

// NameSourceRank returns persistence priority. Higher replaces lower; equal keeps existing.
func NameSourceRank(src string) int {
	switch src {
	case NameSourceHost:
		return 90
	case NameSourceARP:
		return 80
	case NameSourceDNS:
		return 70
	case NameSourceCast:
		return 50
	case NameSourceHTTP:
		return 40
	default:
		return 0
	}
}

// PreferHostname keeps or upgrades a stored hostname using source ranks.
// Lower-ranked candidates never overwrite a higher-ranked stored name.
// Equal rank keeps the existing name (avoids flap between equivalent sources).
func PreferHostname(existingName, existingSource, candidateName, candidateSource string) (name, source string) {
	candidateName = SanitizeHostname(candidateName)
	existingName = SanitizeHostname(existingName)

	if existingName == "" {
		existingSource = NameSourceNone
	}
	if candidateName == "" {
		return existingName, existingSource
	}
	if existingName == "" {
		return candidateName, candidateSource
	}

	if NameSourceRank(candidateSource) > NameSourceRank(existingSource) {
		return candidateName, candidateSource
	}
	return existingName, existingSource
}
