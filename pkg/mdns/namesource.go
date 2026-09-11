package mdns

// Hostname source identifiers (persisted on Device.NameSource).
// Higher rank wins and is sticky against lower-ranked scans.
const (
	NameSourceNone    = ""
	NameSourceHost    = "host"    // this Mac's computer name
	NameSourceDHCP    = "dhcp"    // router DHCP client list
	NameSourceNetBIOS = "netbios" // NetBIOS node status
	NameSourceARP     = "arp"     // macOS arp -a / Bonjour cache
	NameSourceMDNS    = "mdns"    // always-on multicast listener (same rank as ARP)
	NameSourceUPnP    = "upnp"    // UPnP friendlyName
	NameSourceECP     = "ecp"     // Roku ECP owner-assigned name
	NameSourceDNS     = "dns"     // reverse DNS or dns-sd PTR
	NameSourceTLS     = "tls"     // TLS Subject CN
	NameSourceCast    = "cast"    // Chromecast / Nest eureka name
	NameSourceHTTP    = "http"    // HTTP <title>
)

// NameSourceRank returns persistence priority. Higher replaces lower; equal keeps existing.
func NameSourceRank(src string) int {
	switch src {
	case NameSourceHost:
		return 90
	case NameSourceDHCP:
		return 85
	case NameSourceNetBIOS:
		return 82
	case NameSourceARP, NameSourceMDNS:
		return 80
	case NameSourceECP:
		// The owner typed this name into the device itself, so it outranks any
		// protocol-derived name and sits just under the router's DHCP record.
		return 84
	case NameSourceUPnP:
		return 75
	case NameSourceDNS:
		return 70
	case NameSourceTLS:
		return 60
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
	candidateName = normalizeResolvedName(candidateName)
	existingName = normalizeResolvedName(existingName)

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
