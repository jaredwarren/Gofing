package mdns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	dnsTypeA    = 1
	dnsTypePTR  = 12
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33
)

var (
	errDNSTrunc = errors.New("truncated dns message")
	errDNSPtr   = errors.New("dns pointer loop")
	errDNSLabel = errors.New("invalid dns label")
)

type learnedName struct {
	IP       string
	Hostname string
	Hints    FingerprintHints
}

type dnsRR struct {
	Name string
	Type uint16
	Data []byte
	Off  int // offset of RDATA in the original message
}

func parseMDNSMessage(msg []byte) []learnedName {
	rrs, err := parseResourceRecords(msg)
	if err != nil || len(rrs) == 0 {
		return nil
	}

	hostToIP := map[string]string{}
	ipToHost := map[string]string{}
	var txts []dnsRR

	for _, rr := range rrs {
		switch rr.Type {
		case dnsTypeA:
			if len(rr.Data) < 4 {
				continue
			}
			ip := net.IPv4(rr.Data[0], rr.Data[1], rr.Data[2], rr.Data[3]).String()
			if !isUnicastIPv4(ip) {
				continue
			}
			hostToIP[dnsNameKey(rr.Name)] = ip
			if host := hostnameFromOwner(rr.Name); host != "" {
				ipToHost[ip] = host
			}
		case dnsTypePTR:
			target, _, err := readName(msg, rr.Off)
			if err != nil || target == "" {
				continue
			}
			if ip := ipFromReversePTR(rr.Name); ip != "" {
				if host := hostnameFromOwner(target); host != "" {
					ipToHost[ip] = host
				}
			}
		case dnsTypeSRV:
			if len(rr.Data) < 7 {
				continue
			}
			target, _, err := readName(msg, rr.Off+6)
			if err != nil {
				continue
			}
			if host := hostnameFromOwner(target); host != "" {
				if ip := hostToIP[dnsNameKey(target)]; ip != "" {
					ipToHost[ip] = host
				}
			}
		case dnsTypeTXT:
			txts = append(txts, rr)
		}
	}

	// Second pass: SRV targets whose A records were parsed after the SRV.
	for _, rr := range rrs {
		if rr.Type != dnsTypeSRV || len(rr.Data) < 7 {
			continue
		}
		target, _, err := readName(msg, rr.Off+6)
		if err != nil {
			continue
		}
		host := hostnameFromOwner(target)
		ip := hostToIP[dnsNameKey(target)]
		if host != "" && ip != "" {
			ipToHost[ip] = host
		}
	}

	byIP := map[string]*learnedName{}
	order := make([]string, 0)
	put := func(ip, host string) {
		if ip == "" {
			return
		}
		item, ok := byIP[ip]
		if !ok {
			item = &learnedName{IP: ip}
			byIP[ip] = item
			order = append(order, ip)
		}
		if host != "" && item.Hostname == "" {
			item.Hostname = host
		}
	}
	for ip, host := range ipToHost {
		put(ip, host)
	}

	for _, rr := range txts {
		if isLKDCName(rr.Name) || txtContainsLKDC(rr.Data) {
			continue
		}
		kv := parseTXTMap(rr.Data)
		if len(kv) == 0 {
			continue
		}
		st := serviceTypeFromName(rr.Name)
		hints := hintsFromTXT(st, kv)
		ip := hostToIP[dnsNameKey(rr.Name)]
		if ip == "" {
			// TXT owner is often the service instance; A is on the SRV target.
			continue
		}
		put(ip, "")
		byIP[ip].Hints = mergeHints(byIP[ip].Hints, hints)
	}

	out := make([]learnedName, 0, len(order))
	for _, ip := range order {
		item := *byIP[ip]
		if item.Hostname == "" && item.Hints.Model == "" && item.Hints.DeviceType == "" && len(item.Hints.Services) == 0 {
			continue
		}
		out = append(out, item)
	}
	return out
}

func parseResourceRecords(msg []byte) ([]dnsRR, error) {
	if len(msg) < 12 {
		return nil, errDNSTrunc
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	off := 12

	for i := 0; i < qd; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4 // type + class
		if off > len(msg) {
			return nil, errDNSTrunc
		}
	}

	total := an + ns + ar
	var rrs []dnsRR
	for i := 0; i < total; i++ {
		name, next, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, errDNSTrunc
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		off += 4 // type + class (ignore cache-flush)
		off += 4 // TTL
		rdlen := int(binary.BigEndian.Uint16(msg[off : off+2]))
		off += 2
		if rdlen < 0 || off+rdlen > len(msg) {
			return nil, errDNSTrunc
		}
		rrs = append(rrs, dnsRR{
			Name: name,
			Type: typ,
			Data: msg[off : off+rdlen],
			Off:  off,
		})
		off += rdlen
	}
	return rrs, nil
}

func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	jumped := false
	next := offset
	hops := 0
	for {
		if offset >= len(msg) {
			return "", 0, errDNSTrunc
		}
		l := int(msg[offset])
		if l == 0 {
			offset++
			if !jumped {
				next = offset
			}
			break
		}
		switch {
		case l&0xC0 == 0xC0:
			if offset+1 >= len(msg) {
				return "", 0, errDNSTrunc
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			if ptr >= len(msg) {
				return "", 0, errDNSPtr
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ptr
			hops++
			if hops > 16 {
				return "", 0, errDNSPtr
			}
		case l&0xC0 != 0:
			return "", 0, errDNSLabel
		default:
			offset++
			if offset+l > len(msg) {
				return "", 0, errDNSTrunc
			}
			labels = append(labels, string(msg[offset:offset+l]))
			offset += l
			if !jumped {
				next = offset
			}
		}
	}
	return strings.Join(labels, "."), next, nil
}

func hostnameFromOwner(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || isServiceName(name) || isLKDCName(name) || isReverseARPA(name) {
		return ""
	}
	return normalizeResolvedName(name)
}

func isServiceName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.Contains(n, "._tcp.") || strings.Contains(n, "._udp.") {
		return true
	}
	if strings.HasPrefix(n, "_") {
		return true
	}
	return false
}

func isLKDCName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "lkdc")
}

func isReverseARPA(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	return strings.HasSuffix(n, ".in-addr.arpa")
}

func ipFromReversePTR(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	n = strings.TrimSuffix(n, ".in-addr.arpa")
	parts := strings.Split(n, ".")
	if len(parts) != 4 {
		return ""
	}
	ip := net.ParseIP(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	if ip == nil || ip.To4() == nil || !isUnicastIPv4(ip.String()) {
		return ""
	}
	return ip.String()
}

func dnsNameKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func isUnicastIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return !ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func parseTXTMap(data []byte) map[string]string {
	out := make(map[string]string)
	for i := 0; i < len(data); {
		n := int(data[i])
		i++
		if n == 0 || i+n > len(data) {
			break
		}
		s := string(data[i : i+n])
		i += n
		if kv := strings.SplitN(s, "=", 2); len(kv) == 2 {
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			if key != "" && val != "" {
				out[key] = val
			}
		}
	}
	return out
}

func txtContainsLKDC(data []byte) bool {
	return strings.Contains(strings.ToLower(string(data)), "lkdc")
}

func serviceTypeFromName(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	n = strings.TrimSuffix(n, ".local")
	if i := strings.Index(n, "._"); i >= 0 {
		return strings.TrimSuffix(n[i+1:], ".")
	}
	return n
}
