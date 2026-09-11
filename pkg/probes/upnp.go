package probes

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rootXML is the top-level UPnP device descriptor schema.
type rootXML struct {
	XMLName xml.Name  `xml:"root"`
	Device  deviceXML `xml:"device"`
}

type deviceXML struct {
	DeviceType      string `xml:"deviceType"`
	FriendlyName    string `xml:"friendlyName"`
	Manufacturer    string `xml:"manufacturer"`
	ModelName       string `xml:"modelName"`
	ModelNumber     string `xml:"modelNumber"`
	ModelDesc       string `xml:"modelDescription"`
	PresentationURL string `xml:"presentationURL"`
}

// ParseUPnPXML parses a standard UPnP XML device description document.
func ParseUPnPXML(data []byte) (*UPnPInfo, error) {
	var r rootXML
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	info := &UPnPInfo{
		FriendlyName:    strings.TrimSpace(r.Device.FriendlyName),
		Manufacturer:    strings.TrimSpace(r.Device.Manufacturer),
		ModelName:       strings.TrimSpace(r.Device.ModelName),
		ModelNumber:     strings.TrimSpace(r.Device.ModelNumber),
		ModelDesc:       strings.TrimSpace(r.Device.ModelDesc),
		DeviceType:      strings.TrimSpace(r.Device.DeviceType),
		PresentationURL: strings.TrimSpace(r.Device.PresentationURL),
	}
	return info, nil
}

// ProbeUPnP sends a unicast SSDP discovery packet to the target IP on port 1900
// and fetches the device XML descriptor if a LOCATION header is returned.
func ProbeUPnP(ctx context.Context, ip string) (*UPnPInfo, error) {
	target := net.JoinHostPort(ip, "1900")
	conn, err := net.DialTimeout("udp", target, 750*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Deadline for both write and read
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(1200 * time.Millisecond)
	}
	_ = conn.SetDeadline(deadline)

	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + target + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(msearch)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	respStr := string(buf[:n])
	var location string
	var serverHeader string

	lines := strings.Split(respStr, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "location:") {
			location = strings.TrimSpace(line[len("location:"):])
		} else if strings.HasPrefix(lower, "server:") {
			serverHeader = strings.TrimSpace(line[len("server:"):])
		}
	}

	if location == "" {
		return nil, fmt.Errorf("no location header in ssdp response")
	}

	// Fetch the device XML document with short timeout
	reqCtx, reqCancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: 1200 * time.Millisecond,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	httpResp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status fetching upnp xml: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 128*1024))
	if err != nil {
		return nil, err
	}

	info, err := ParseUPnPXML(body)
	if err != nil {
		return nil, err
	}

	info.Location = location
	info.ServerHeader = serverHeader

	// If presentationURL is relative, resolve against location URL
	if info.PresentationURL != "" && !strings.HasPrefix(info.PresentationURL, "http://") && !strings.HasPrefix(info.PresentationURL, "https://") {
		if locURL, err := url.Parse(location); err == nil {
			info.PresentationURL = locURL.ResolveReference(&url.URL{Path: info.PresentationURL}).String()
		}
	}

	return info, nil
}
