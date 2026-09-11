package probes

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// rokuECPPort is Roku's External Control Protocol port. It serves device
// identity over plain HTTP with no authentication.
const rokuECPPort = 8060

type rokuDeviceInfoXML struct {
	XMLName        xml.Name `xml:"device-info"`
	UserDeviceName string   `xml:"user-device-name"`
	FriendlyName   string   `xml:"friendly-device-name"`
	ModelName      string   `xml:"model-name"`
	ModelNumber    string   `xml:"model-number"`
	VendorName     string   `xml:"vendor-name"`
	SerialNumber   string   `xml:"serial-number"`
	SoftwareVer    string   `xml:"software-version"`
	DeviceID       string   `xml:"device-id"`
}

func parseRokuDeviceInfo(data []byte) (*RokuInfo, error) {
	var d rokuDeviceInfoXML
	if err := xml.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	info := &RokuInfo{
		// The user-assigned name ("Living room 2") is the useful one; the
		// friendly name is usually a duplicate of the model.
		Name:         firstNonEmpty(d.UserDeviceName, d.FriendlyName),
		ModelName:    strings.TrimSpace(d.ModelName),
		ModelNumber:  strings.TrimSpace(d.ModelNumber),
		VendorName:   strings.TrimSpace(d.VendorName),
		SerialNumber: strings.TrimSpace(d.SerialNumber),
		SoftwareVer:  strings.TrimSpace(d.SoftwareVer),
	}
	if info.Name == "" && info.ModelName == "" && info.VendorName == "" {
		return nil, fmt.Errorf("probes: not a Roku device-info document")
	}
	return info, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// probeRoku fetches identity from a Roku's ECP endpoint.
//
// Worth a dedicated probe because a Roku answers neither ICMP reliably nor any
// of the other identity protocols, yet hands over its owner-assigned name,
// exact model and serial for one unauthenticated GET.
func probeRoku(ctx context.Context, ip string) (*RokuInfo, error) {
	if ip == "" {
		return nil, fmt.Errorf("probes: no ip")
	}
	url := fmt.Sprintf("http://%s/query/device-info",
		net.JoinHostPort(ip, fmt.Sprint(rokuECPPort)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probes: roku ECP returned %d", resp.StatusCode)
	}
	// Bounded read: this is an unauthenticated endpoint on an untrusted LAN.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseRokuDeviceInfo(body)
}
