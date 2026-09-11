package probes

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

var netbiosNodeStatusReq = []byte{
	0x82, 0x28, // Transaction ID
	0x00, 0x10, // Flags: broadcast query
	0x00, 0x01, // Questions: 1
	0x00, 0x00, // Answer RRs: 0
	0x00, 0x00, // Authority RRs: 0
	0x00, 0x00, // Additional RRs: 0
	0x20, // Name length: 32
	'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	0x00,       // Terminator
	0x00, 0x21, // Type: NBSTAT (33)
	0x00, 0x01, // Class: IN (1)
}

func parseNetBIOSResponse(data []byte) (*NetBIOSInfo, error) {
	if len(data) < 56 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Look for the answers count at offset 6
	answers := binary.BigEndian.Uint16(data[6:8])
	if answers == 0 {
		return nil, fmt.Errorf("no answers in response")
	}

	// Find the RDATA section by looking for NBSTAT (0x0021) in answer
	// Typically the answer starts around byte 56. Let's find 0x00, 0x21
	idx := -1
	for i := 12; i < len(data)-10; i++ {
		if data[i] == 0x00 && data[i+1] == 0x21 {
			// Type (2) + Class (2) + TTL (4) + RDLENGTH (2) = 10 bytes to RDATA
			idx = i + 10
			break
		}
	}
	if idx < 0 || idx >= len(data) {
		return nil, fmt.Errorf("unable to locate NBSTAT rdata")
	}

	// Number of names
	numNames := int(data[idx])
	idx++

	info := &NetBIOSInfo{}

	for i := 0; i < numNames && idx+18 <= len(data); i++ {
		rawName := data[idx : idx+15]
		suffix := data[idx+15]
		flags := binary.BigEndian.Uint16(data[idx+16 : idx+18])
		idx += 18

		name := strings.TrimSpace(string(rawName))
		isGroup := (flags & 0x8000) != 0

		if isGroup {
			if suffix == 0x00 && info.Workgroup == "" {
				info.Workgroup = name
			}
		} else {
			if suffix == 0x00 && info.ComputerName == "" {
				info.ComputerName = name
			} else if suffix == 0x20 && info.ComputerName == "" {
				info.ComputerName = name
			} else if suffix == 0x03 && info.UserName == "" {
				info.UserName = name
			}
		}
	}

	// Following the names table is the 6-byte unit ID (hardware MAC address)
	if idx+6 <= len(data) {
		mac := data[idx : idx+6]
		info.MAC = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}

	if info.ComputerName == "" && info.Workgroup == "" {
		return nil, fmt.Errorf("no computer or workgroup name found in netbios payload")
	}

	return info, nil
}

func probeNetBIOS(ctx context.Context, ip string) (*NetBIOSInfo, error) {
	target := net.JoinHostPort(ip, "137")
	conn, err := net.DialTimeout("udp", target, 750*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(1000 * time.Millisecond)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(netbiosNodeStatusReq); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return parseNetBIOSResponse(buf[:n])
}
