package network

import (
	"net"
	"testing"
)

func TestIsInSubnet(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	if !isInSubnet("192.168.1.1", subnet) {
		t.Errorf("expected 192.168.1.1 to be in 192.168.1.0/24")
	}

	if isInSubnet("192.168.2.1", subnet) {
		t.Errorf("expected 192.168.2.1 NOT to be in 192.168.1.0/24")
	}
}

func TestGetActiveNetworkInfo(t *testing.T) {
	info, err := GetActiveNetworkInfo()
	if err != nil {
		t.Skipf("Skipping interface test if no active network: %v", err)
		return
	}

	if info.IP == "" {
		t.Errorf("expected IP to be set")
	}
	if info.SubnetCIDR == "" {
		t.Errorf("expected SubnetCIDR to be set")
	}
	t.Logf("Detected network info: IP=%s, Subnet=%s, Gateway=%s, SSID=%s, Iface=%s",
		info.IP, info.SubnetCIDR, info.GatewayIP, info.SSID, info.InterfaceName)
}
