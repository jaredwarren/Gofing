package mdns

import (
	"regexp"
	"strings"
)

// FingerprintHints are model/type/service clues gleaned from dns-sd TXT records.
type FingerprintHints struct {
	Model      string
	DeviceType string
	Icon       string
	Services   []string
}

var (
	txtPairRe = regexp.MustCompile(`(?i)(?:^|[\s"])([a-z0-9_-]+)=([^"\s]+)`)
)

// parseDNSSDLookupOutput extracts hostname and TXT key/values from dns-sd -L text.
func parseDNSSDLookupOutput(output string) (hostname string, txt map[string]string) {
	txt = make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		if hostname == "" {
			if m := reachedAtHostRe.FindStringSubmatch(line); len(m) >= 2 {
				host := strings.TrimSuffix(m[1], ".")
				if clean := normalizeResolvedName(host); clean != "" {
					hostname = clean
				}
			}
		}
		for _, m := range txtPairRe.FindAllStringSubmatch(line, -1) {
			if len(m) < 3 {
				continue
			}
			key := strings.ToLower(m[1])
			val := strings.TrimSpace(m[2])
			val = strings.Trim(val, `"'`)
			if val == "" {
				continue
			}
			txt[key] = val
		}
	}
	return hostname, txt
}

// hintsFromTXT maps common Bonjour TXT keys to device fingerprint fields.
func hintsFromTXT(serviceType string, txt map[string]string) FingerprintHints {
	var h FingerprintHints
	st := strings.ToLower(serviceType)

	if m := firstTXT(txt, "model", "md", "am", "ty"); m != "" {
		h.Model = humanizeModel(m)
	}
	if fn := firstTXT(txt, "fn", "friendlyname", "name"); fn != "" && h.Model == "" {
		if SanitizeHostname(fn) != "" {
			h.Model = SanitizeHostname(fn)
		}
	}

	switch {
	case strings.Contains(st, "_airplay") || strings.Contains(st, "_raop") || strings.Contains(st, "_companion-link"):
		h.Services = append(h.Services, "AirPlay")
		if h.DeviceType == "" {
			h.DeviceType, h.Icon = appleTypeFromModel(h.Model)
		}
	case strings.Contains(st, "_googlecast"):
		h.Services = append(h.Services, "Google Cast")
		h.DeviceType, h.Icon = "Smart TV", "tv"
		if h.Model == "" {
			h.Model = "Google Nest / Chromecast"
		}
	case strings.Contains(st, "_printer") || strings.Contains(st, "_ipp"):
		h.Services = append(h.Services, "Printer")
		h.DeviceType, h.Icon = "Printer", "printer"
		if h.Model == "" {
			h.Model = "Network Printer"
		}
	case strings.Contains(st, "_smb") || strings.Contains(st, "_afpovertcp"):
		h.Services = append(h.Services, "File Share (SMB)")
	case strings.Contains(st, "_hap") || strings.Contains(st, "_homekit"):
		h.Services = append(h.Services, "HomeKit")
		if h.DeviceType == "" {
			h.DeviceType, h.Icon = "Smart Home / IoT", "iot"
		}
	case strings.Contains(st, "_ssh") || strings.Contains(st, "_sftp"):
		h.Services = append(h.Services, "SSH")
	case strings.Contains(st, "_http"):
		h.Services = append(h.Services, "HTTP")
	}

	if strings.Contains(strings.ToLower(h.Model), "appletv") || strings.Contains(strings.ToLower(h.Model), "apple tv") {
		h.DeviceType, h.Icon = "Smart TV", "tv"
		h.Model = "Apple TV"
	}
	if strings.Contains(strings.ToLower(h.Model), "homepod") {
		h.DeviceType, h.Icon = "Smart Speaker", "speaker"
		h.Model = "Apple HomePod"
	}
	return h
}

func firstTXT(txt map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := txt[k]; v != "" {
			return v
		}
	}
	return ""
}

func humanizeModel(m string) string {
	m = strings.TrimSpace(m)
	switch strings.ToLower(m) {
	case "appletv", "appletv14,1", "appletv11,1", "appletv6,2":
		return "Apple TV"
	case "audiodevice1,1", "audiodevice1,2":
		return "Apple HomePod"
	}
	// MacBookPro18,1 → MacBook Pro
	lower := strings.ToLower(m)
	for _, prefix := range []struct{ raw, nice string }{
		{"macbookpro", "MacBook Pro"},
		{"macbookair", "MacBook Air"},
		{"macbook", "MacBook"},
		{"imac", "iMac"},
		{"macmini", "Mac mini"},
		{"macpro", "Mac Pro"},
		{"macstudio", "Mac Studio"},
		{"iphone", "Apple iPhone"},
		{"ipad", "Apple iPad"},
	} {
		if strings.HasPrefix(lower, prefix.raw) {
			return prefix.nice
		}
	}
	return m
}

func appleTypeFromModel(model string) (devType, icon string) {
	lower := strings.ToLower(model)
	switch {
	case strings.Contains(lower, "iphone"):
		return "Mobile Phone", "smartphone"
	case strings.Contains(lower, "ipad"):
		return "Tablet", "tablet"
	case strings.Contains(lower, "tv"):
		return "Smart TV", "tv"
	case strings.Contains(lower, "homepod") || strings.Contains(lower, "speaker"):
		return "Smart Speaker", "speaker"
	case model != "":
		return "Computer", "laptop"
	default:
		return "Apple Device", "laptop"
	}
}

func mergeHints(base, extra FingerprintHints) FingerprintHints {
	if extra.Model != "" {
		base.Model = extra.Model
	}
	if extra.DeviceType != "" {
		base.DeviceType = extra.DeviceType
		base.Icon = extra.Icon
	}
	base.Services = uniqueStrings(append(base.Services, extra.Services...))
	return base
}
