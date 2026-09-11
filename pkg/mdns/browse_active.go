package mdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// DefaultBrowseServices are the service types worth asking about on a home LAN.
//
// The ordering is by how much identity they tend to yield. Apple's
// _companion-link and _rdlink carry the owner-assigned device name ("Amy's
// MacBook Pro") and are the only practical handle on a device using a
// randomized MAC, which defeats vendor lookup by design. _hap (HomeKit),
// _googlecast and _spotify-connect name smart-home and media hardware that
// often answers nothing else at all.
var DefaultBrowseServices = []string{
	"_companion-link._tcp.local",
	"_rdlink._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
	"_homekit._tcp.local",
	"_hap._tcp.local",
	"_googlecast._tcp.local",
	"_spotify-connect._tcp.local",
	"_printer._tcp.local",
	"_ipp._tcp.local",
	"_smb._tcp.local",
	"_ssh._tcp.local",
	"_http._tcp.local",
	"_workstation._tcp.local",
	"_device-info._tcp.local",
}

const (
	dnsClassIN  = 1
	mdnsPort    = 5353
	maxQuestion = 255
)

var errNoServices = errors.New("mdns: no service types to browse")

// buildServiceQuery encodes one mDNS packet asking for PTR records for every
// named service type.
//
// The unicast-response bit is deliberately left clear, so responders multicast
// their answers to 224.0.0.251 where the always-on listener already sees them.
// That is what lets an active browse reuse the passive parser instead of
// needing its own receive path and its own cache.
func buildServiceQuery(serviceTypes []string) ([]byte, error) {
	var questions [][]byte
	for _, svc := range serviceTypes {
		name, err := encodeDNSName(svc)
		if err != nil {
			slog.Debug("mdns: skipping unencodable service type", "service", svc, "error", err)
			continue
		}
		q := make([]byte, 0, len(name)+4)
		q = append(q, name...)
		q = binary.BigEndian.AppendUint16(q, dnsTypePTR)
		q = binary.BigEndian.AppendUint16(q, dnsClassIN)
		questions = append(questions, q)
	}
	if len(questions) == 0 {
		return nil, errNoServices
	}

	msg := make([]byte, 12)
	// ID 0 and flags 0: a standard multicast DNS query. QDCOUNT follows.
	binary.BigEndian.PutUint16(msg[4:6], uint16(len(questions)))
	for _, q := range questions {
		msg = append(msg, q...)
	}
	return msg, nil
}

// encodeDNSName writes a dotted name in DNS label form.
func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, errors.New("mdns: empty name")
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("mdns: empty label in %q", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("mdns: label too long in %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > maxQuestion {
		return nil, fmt.Errorf("mdns: name too long: %q", name)
	}
	return out, nil
}

// Browse asks the network which hosts offer the given service types.
//
// This is the active counterpart to the always-on listener. Passive listening
// only learns about a device when it chooses to announce itself, which can be
// never for a device that is already associated and idle; a browse prompts it
// to answer now. Responses are collected by the listener, so this returns as
// soon as the queries are sent and names appear in the cache shortly after.
//
// serviceTypes may be nil, in which case DefaultBrowseServices is used.
func (r *Resolver) Browse(ctx context.Context, ifaceName string, serviceTypes []string) error {
	if r == nil {
		return errors.New("mdns: nil resolver")
	}
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return errors.New("mdns: no interface")
	}
	if len(serviceTypes) == 0 {
		serviceTypes = DefaultBrowseServices
	}
	msg, err := buildServiceQuery(serviceTypes)
	if err != nil {
		return err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	// A separate ephemeral socket: the listener's multicast socket is owned by
	// its read loop, and sending from here keeps the two paths independent.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := bindMulticastInterface(conn, iface); err != nil {
		slog.Debug("mdns: could not pin multicast interface", "iface", ifaceName, "error", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetWriteDeadline(deadline)

	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}
	// Two sends a short interval apart: mDNS is unreliable by design and a
	// single lost query means a silent device stays unnamed for a whole cycle.
	var sendErr error
	for i := 0; i < 2; i++ {
		if _, err := conn.WriteToUDP(msg, group); err != nil {
			sendErr = err
			break
		}
		if i == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(120 * time.Millisecond):
			}
		}
	}
	if sendErr != nil {
		return sendErr
	}
	slog.Debug("mdns browse sent", "iface", ifaceName, "services", len(serviceTypes), "bytes", len(msg))
	return nil
}
