package mdns

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindMulticastInterface pins outgoing multicast to one interface, so a browse
// goes out the LAN the scan is actually about rather than whichever interface
// the routing table prefers.
func bindMulticastInterface(conn *net.UDPConn, iface *net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	var v4 net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				v4 = ip4
				break
			}
		}
	}
	if v4 == nil {
		return syscall.EADDRNOTAVAIL
	}

	var opErr error
	err = raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInet4Addr(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF,
			[4]byte{v4[0], v4[1], v4[2], v4[3]})
	})
	if err != nil {
		return err
	}
	return opErr
}
