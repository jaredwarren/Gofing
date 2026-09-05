package dhcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseClientListFourLine(t *testing.T) {
	text := `Device Name
MAC Address
IP Address
Lease Time
Amys-MBP
8C:85:90:24:10:B7
192.168.0.142
01:22:10
---
AA:BB:CC:DD:EE:01
192.168.0.10
00:05:00
GamingLaptop
70:4D:7B:11:22:33
192.168.0.66
12:00:00
`
	got := Parse([]byte(text))
	if len(got) != 2 {
		t.Fatalf("got %d leases: %+v", len(got), got)
	}
	if got[0].Hostname != "Amys-MBP" || got[0].MAC != "8C:85:90:24:10:B7" || got[0].IP != "192.168.0.142" {
		t.Fatalf("first=%+v", got[0])
	}
	if got[1].Hostname != "GamingLaptop" {
		t.Fatalf("second=%+v", got[1])
	}
}

func TestParseJSON(t *testing.T) {
	got := Parse([]byte(`[{"hostname":"Pixel-10","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.0.51"}]`))
	if len(got) != 1 || got[0].Hostname != "Pixel-10" || got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("%+v", got)
	}

	got = Parse([]byte(`{"clients":[{"name":"iPad","mac":"11:22:33:44:55:66","ip":"10.0.0.8"}]}`))
	if len(got) != 1 || got[0].Hostname != "iPad" {
		t.Fatalf("wrapped=%+v", got)
	}
}

func TestParseCSV(t *testing.T) {
	got := Parse([]byte("Amys-MBP,8C:85:90:24:10:B7,192.168.0.142\n"))
	if len(got) != 1 || got[0].Hostname != "Amys-MBP" || got[0].IP != "192.168.0.142" {
		t.Fatalf("%+v", got)
	}
}

func TestParseFileMissing(t *testing.T) {
	_, err := ParseFile(filepath.Join(t.TempDir(), "nope.txt"))
	if !os.IsNotExist(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestParseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.txt")
	if err := os.WriteFile(path, []byte("Watch\n70:22:FE:00:11:22\n192.168.0.83\n00:10:00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Hostname != "Watch" {
		t.Fatalf("%+v", got)
	}
}

func TestSourceFetchUnionsByMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp.txt")
	if err := os.WriteFile(path, []byte("OldName\n8C:85:90:24:10:B7\n192.168.0.142\n00:01:00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := Source{File: path}
	got, err := src.Fetch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Hostname != "OldName" {
		t.Fatalf("%+v", got)
	}

	src.File = filepath.Join(dir, "missing.txt")
	got, err = src.Fetch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("missing file should yield empty, got %+v", got)
	}
}
