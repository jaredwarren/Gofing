package mdns

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"
)

const mdnsMaxPacket = 9000

// Listen joins IPv4 mDNS multicast on ifaceName and reads until ctx is cancelled.
// Rebinding the same interface is a no-op; a different interface cancels the old loop.
func (r *Resolver) Listen(ctx context.Context, ifaceName string) {
	if r == nil {
		return
	}
	ifaceName = strings.TrimSpace(ifaceName)
	if ctx == nil || ifaceName == "" {
		return
	}

	r.listenMu.Lock()
	defer r.listenMu.Unlock()
	if r.listenCancel != nil && r.listenIface == ifaceName {
		return
	}
	if r.listenCancel != nil {
		r.listenCancel()
		r.listenCancel = nil
	}

	lctx, cancel := context.WithCancel(ctx)
	r.listenCancel = cancel
	r.listenIface = ifaceName
	go r.readLoop(lctx, ifaceName)
}

func (r *Resolver) readLoop(ctx context.Context, ifaceName string) {
	conn, err := listenMDNS(ifaceName)
	if err != nil {
		slog.Warn("mDNS listener failed to join multicast", "iface", ifaceName, "error", err)
		return
	}
	defer conn.Close()
	slog.Info("mDNS listener joined", "iface", ifaceName, "group", "224.0.0.251:5353")

	buf := make([]byte, mdnsMaxPacket)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			slog.Debug("mDNS read error", "error", err)
			continue
		}
		if n <= 0 {
			continue
		}
		learned := parseMDNSMessage(buf[:n])
		if len(learned) == 0 {
			continue
		}
		r.ingestLearned(learned)
	}
}

func (r *Resolver) ingestLearned(learned []learnedName) {
	handler := r.nameHandler()
	for _, item := range learned {
		if item.IP == "" {
			continue
		}
		before := r.cachedForIP(item.IP)
		if item.Hostname != "" {
			r.rememberIPName(item.IP, item.Hostname, NameSourceMDNS)
		}
		if item.Hints.Model != "" || item.Hints.DeviceType != "" || len(item.Hints.Services) > 0 {
			r.rememberIPHints(item.IP, item.Hints)
		}
		after := r.cachedForIP(item.IP)
		if handler == nil || after.Hostname == "" {
			continue
		}
		if after.Hostname == before.Hostname && after.Source == before.Source {
			continue
		}
		handler(item.IP, after.Hostname, after.Source)
	}
}

func (r *Resolver) nameHandler() NameLearnedFunc {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.onLearned
}

func listenMDNS(ifaceName string) (*net.UDPConn, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadBuffer(mdnsMaxPacket * 8); err != nil {
		slog.Debug("mDNS SetReadBuffer", "error", err)
	}
	return conn, nil
}
