package dhcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Lease is a DHCP client-list row: hostname bound to a MAC (and usually an IP).
type Lease struct {
	Hostname string
	MAC      string
	IP       string
}

// Source is a pollable DHCP lease feed. File and URL are optional; missing
// files are skipped so a default path can be watched before the user exports.
type Source struct {
	File string
	URL  string
}

// Fetch reads configured sources and unions leases by MAC (later sources win).
func (s Source) Fetch(ctx context.Context) ([]Lease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	byMAC := map[string]Lease{}
	order := make([]string, 0)

	add := func(leases []Lease) {
		for _, l := range leases {
			mac := strings.ToUpper(strings.TrimSpace(l.MAC))
			if mac == "" {
				continue
			}
			if _, ok := byMAC[mac]; !ok {
				order = append(order, mac)
			}
			byMAC[mac] = l
		}
	}

	if s.File != "" {
		leases, err := ParseFile(s.File)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		add(leases)
	}

	if s.URL != "" {
		leases, err := FetchURL(ctx, s.URL)
		if err != nil {
			return nil, err
		}
		add(leases)
	}

	out := make([]Lease, 0, len(order))
	for _, mac := range order {
		out = append(out, byMAC[mac])
	}
	return out, nil
}

// ParseFile reads a DHCP client-list export from disk.
func ParseFile(path string) ([]Lease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data), nil
}

// FetchURL GETs a user-configured lease document (JSON or client-list text).
func FetchURL(ctx context.Context, rawURL string) ([]Lease, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("empty dhcp url")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dhcp url: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return Parse(body), nil
}
