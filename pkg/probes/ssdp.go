package probes

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// SSDPResponder is one host that answered a multicast M-SEARCH.
type SSDPResponder struct {
	IP       string `json:"ip"`
	Location string `json:"location,omitempty"`
	Server   string `json:"server,omitempty"`
	USN      string `json:"usn,omitempty"`
	ST       string `json:"st,omitempty"`
}

// ssdpMSearch is a standard root-device discovery. MX is the maximum seconds a
// responder may wait before replying, which staggers replies to avoid a storm.
const ssdpMSearch = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: upnp:rootdevice\r\n" +
	"\r\n"

// DiscoverSSDP multicasts an M-SEARCH and collects the responders.
//
// The per-device probeUPnP sends a *unicast* M-SEARCH to one address, which
// only works for a host that both listens on unicast 1900 and is known to be
// there. A multicast search instead asks the whole segment at once and returns
// each responder's own LOCATION, which is the authoritative descriptor URL
// rather than a guessed path — and it finds devices that were not in inventory
// at all.
//
// Returns responders keyed by IP. A host answering several times (once per
// root device) is merged, first answer winning.
func DiscoverSSDP(ctx context.Context, ifaceIP string, wait time.Duration) (map[string]SSDPResponder, error) {
	if wait <= 0 {
		wait = 3 * time.Second
	}
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if ifaceIP != "" {
		if ip := net.ParseIP(ifaceIP); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				laddr = &net.UDPAddr{IP: ip4, Port: 0}
			}
		}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if _, err := conn.WriteToUDP([]byte(ssdpMSearch), group); err != nil {
		return nil, err
	}

	found := make(map[string]SSDPResponder)
	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			break
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				break // the collection window closed; this is the normal exit
			}
			break
		}
		if n <= 0 || addr == nil {
			continue
		}
		ip := addr.IP.String()
		if _, seen := found[ip]; seen {
			continue
		}
		r, err := parseSSDPResponse(buf[:n])
		if err != nil {
			continue
		}
		r.IP = ip
		found[ip] = r
	}
	return found, nil
}

func parseSSDPResponse(data []byte) (SSDPResponder, error) {
	var r SSDPResponder
	rd := bufio.NewReader(bytes.NewReader(data))
	line, err := rd.ReadString('\n')
	if err != nil {
		return r, err
	}
	if !strings.HasPrefix(strings.ToUpper(line), "HTTP/1.1 200") {
		return r, errors.New("probes: not an SSDP 200 response")
	}
	hdr, err := textproto.NewReader(rd).ReadMIMEHeader()
	if err != nil {
		return r, err
	}
	r.Location = strings.TrimSpace(hdr.Get("Location"))
	r.Server = strings.TrimSpace(hdr.Get("Server"))
	r.USN = strings.TrimSpace(hdr.Get("Usn"))
	r.ST = strings.TrimSpace(hdr.Get("St"))
	if r.Location == "" && r.Server == "" && r.USN == "" {
		return r, errors.New("probes: SSDP response carried no identity")
	}
	return r, nil
}
