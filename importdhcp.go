//go:build ignore

// One-shot importer: go run importdhcp.go sample.log
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/mdns"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/oui"
	"github.com/jaredwarren/Gofing/pkg/store"
)

type dhcpRow struct {
	Name string
	MAC  string
	IP   string
}

func main() {
	path := "sample.log"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	rows, err := parseDHCPLog(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}

	db, err := store.Open(store.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	existing, err := db.LoadDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}

	netKey := ""
	counts := map[string]int{}
	for _, d := range existing {
		if d.NetworkKey != "" {
			counts[d.NetworkKey]++
		}
	}
	best := 0
	for k, n := range counts {
		if n > best {
			best = n
			netKey = k
		}
	}
	if netKey == "" {
		if info, err := network.GetActiveNetworkInfo(); err == nil {
			netKey = engine.NetworkKeyFromInfo(info)
		}
	}

	byMAC := map[string][]int{}
	for i, d := range existing {
		mac := engine.NormalizeMAC(d.MAC)
		if mac == "" {
			continue
		}
		byMAC[mac] = append(byMAC[mac], i)
	}

	now := time.Now()
	updated, created, skipped := 0, 0, 0
	var toSave []engine.Device

	for _, row := range rows {
		if row.Name == "" || row.Name == "---" {
			skipped++
			continue
		}
		mac := engine.NormalizeMAC(row.MAC)
		if mac == "" {
			fmt.Fprintf(os.Stderr, "skip bad MAC %q\n", row.MAC)
			skipped++
			continue
		}

		idxs := byMAC[mac]
		if len(idxs) == 0 {
			host, src := mdns.PreferHostname("", mdns.NameSourceNone, row.Name, mdns.NameSourceDHCP)
			dev := engine.Device{
				ID:           engine.ScopedDeviceID(netKey, mac, row.IP),
				NetworkKey:   netKey,
				IP:           row.IP,
				MAC:          mac,
				Vendor:       oui.LookupVendor(mac),
				Hostname:     host,
				NameSource:   src,
				DeviceType:   "Network Device",
				Icon:         "device",
				Model:        host,
				IsOnline:     false,
				IsPrivateMAC: engine.IsPrivateMAC(mac),
				FirstSeen:    now,
				LastSeen:     now,
			}
			existing = append(existing, dev)
			byMAC[mac] = []int{len(existing) - 1}
			toSave = append(toSave, dev)
			created++
			fmt.Printf("created  %s  %s  %s\n", host, mac, row.IP)
			continue
		}

		for _, i := range idxs {
			d := existing[i]
			before := d.Hostname
			d.Hostname, d.NameSource = mdns.PreferHostname(d.Hostname, d.NameSource, row.Name, mdns.NameSourceDHCP)
			if row.IP != "" {
				d.IP = row.IP
			}
			if d.NetworkKey == "" && netKey != "" {
				d.NetworkKey = netKey
			}
			existing[i] = d
			toSave = append(toSave, d)
			if d.Hostname != before {
				updated++
				fmt.Printf("updated  %s → %s  %s  %s\n", before, d.Hostname, mac, d.IP)
			} else {
				fmt.Printf("kept     %s  (%s)  %s\n", d.Hostname, d.NameSource, mac)
			}
		}
	}

	if err := db.SaveDevices(toSave); err != nil {
		fmt.Fprintf(os.Stderr, "save: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nDHCP import: %d updated, %d created, %d skipped (unnamed), %d rows with names\n",
		updated, created, skipped, len(rows)-skipped)
}

func parseDHCPLog(path string) ([]dhcpRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "Device Name") && strings.Contains(line, "MAC") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	var rows []dhcpRow
	for i := 0; i+3 < len(lines); i += 4 {
		rows = append(rows, dhcpRow{
			Name: lines[i],
			MAC:  lines[i+1],
			IP:   lines[i+2],
		})
	}
	return rows, nil
}
