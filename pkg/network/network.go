package network

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Info holds metadata about the active macOS network interface.
type Info struct {
	InterfaceName string `json:"interface_name"`
	IP            string `json:"ip"`
	SubnetCIDR    string `json:"subnet_cidr"`
	Netmask       string `json:"netmask"`
	GatewayIP     string `json:"gateway_ip"`
	SSID          string `json:"ssid"`
	MAC           string `json:"mac"`
	ComputerName  string `json:"computer_name"`
}

// GetActiveNetworkInfo inspects the system to find the primary IPv4 network interface, gateway, and SSID.
func GetActiveNetworkInfo() (*Info, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	gatewayIP := getmacOSGatewayIP()

	var bestInfo *Info

	for _, iface := range ifaces {
		// Ignore down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}

			ipv4 := ipNet.IP.To4()
			if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsLinkLocalUnicast() {
				continue
			}

			mask := ipNet.Mask
			maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
			subnet := ipNet.IP.Mask(mask).String()

			ones, _ := mask.Size()
			cidr := fmt.Sprintf("%s/%d", subnet, ones)

			ssid := getmacOSSSID(iface.Name)

			info := &Info{
				InterfaceName: iface.Name,
				IP:            ipv4.String(),
				SubnetCIDR:    cidr,
				Netmask:       maskStr,
				GatewayIP:     gatewayIP,
				SSID:          ssid,
				MAC:           iface.HardwareAddr.String(),
				ComputerName:  getmacOSComputerName(),
			}

			// Prefer interface matching the subnet of gateway IP if possible
			if gatewayIP != "" && isInSubnet(gatewayIP, ipNet) {
				return info, nil
			}

			if bestInfo == nil {
				bestInfo = info
			}
		}
	}

	if bestInfo != nil {
		return bestInfo, nil
	}

	return nil, fmt.Errorf("no active non-loopback IPv4 interface found")
}

func getmacOSComputerName() string {
	cmd := exec.Command("scutil", "--get", "ComputerName")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		name := strings.TrimSpace(out.String())
		if name != "" {
			return name
		}
	}
	return ""
}

func getmacOSGatewayIP() string {
	cmd := exec.Command("route", "-n", "get", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}

	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

func getmacOSSSID(ifaceName string) string {
	// Try networksetup tool first
	cmd := exec.Command("/usr/sbin/networksetup", "-getairportnetwork", ifaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		str := strings.TrimSpace(out.String())
		if strings.Contains(str, "Current Wi-Fi Network:") {
			parts := strings.Split(str, "Current Wi-Fi Network:")
			if len(parts) == 2 {
				ssid := strings.TrimSpace(parts[1])
				if ssid != "" {
					return ssid
				}
			}
		}
	}

	// Try airport binary if present
	airportPath := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	cmd2 := exec.Command(airportPath, "-I")
	var out2 bytes.Buffer
	cmd2.Stdout = &out2
	if err := cmd2.Run(); err == nil {
		for _, line := range strings.Split(out2.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SSID:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return "Wired / Ethernet"
}

func isInSubnet(ipStr string, subnet *net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return subnet.Contains(ip)
}
