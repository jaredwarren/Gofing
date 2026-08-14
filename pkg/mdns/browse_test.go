package mdns

import "testing"

func TestParseReachedAtHost(t *testing.T) {
	line := `16:00:00.000  ...  Amy's MacBook._companion-link._tcp.local. can be reached at AMYS-MBP.local.:7000 (interface 14)`
	if got := parseReachedAtHost(line); got != "AMYS-MBP" {
		t.Fatalf("got %q want AMYS-MBP", got)
	}
}

func TestParseReachedAtIP(t *testing.T) {
	line := `16:00:00.000  ...  AMYS-MBP.local. can be reached at 192.168.0.142:0 (interface 14)`
	if got := parseReachedAtIP(line); got != "192.168.0.142" {
		t.Fatalf("got %q", got)
	}
}

func TestParseBrowseAddInstance(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{
			line: `18:13:44.894  Add        3  14 local.               _companion-link._tcp. iPad (73)`,
			want: "iPad (73)",
		},
		{
			line: `18:13:44.894  Add        3  14 local.               _companion-link._tcp. Jared’s MacBook Pro  M4`,
			want: "Jared’s MacBook Pro M4",
		},
		{
			line: `18:14:45.693  Add        2  14 local.               _workstation._tcp.   calendar [2c:cf:67:2d:ae:b4]`,
			want: "calendar [2c:cf:67:2d:ae:b4]",
		},
		{
			line: `18:13:44.894  Add        2  14 local.               _companion-link._tcp. iPad (89)`,
			want: "iPad (89)",
		},
		{
			line: `Timestamp     A/R    Flags  if Domain               Service Type         Instance Name`,
			want: "",
		},
		{
			line: `18:13:44.894  ...STARTING...`,
			want: "",
		},
	}
	for _, tt := range tests {
		got := parseBrowseAddInstance(tt.line)
		if got != tt.want {
			t.Errorf("parseBrowseAddInstance(%q)\n got %q\nwant %q", tt.line, got, tt.want)
		}
	}
}

func TestRememberIPNameUpgrade(t *testing.T) {
	r := &Resolver{mdnsCache: map[string]string{}, ipNames: map[string]cachedName{}, ipHints: map[string]FingerprintHints{}}
	r.rememberIPName("192.168.0.142", "Router Admin", NameSourceHTTP)
	r.rememberIPName("192.168.0.142", "amys-mbp", NameSourceARP)
	c := r.cachedForIP("192.168.0.142")
	if c.Hostname != "amys-mbp" || c.Source != NameSourceARP {
		t.Fatalf("cache=%+v", c)
	}
}

func TestLookupHostnameQuickUsesCache(t *testing.T) {
	r := &Resolver{mdnsCache: map[string]string{}, ipNames: map[string]cachedName{}, ipHints: map[string]FingerprintHints{}}
	r.rememberIPName("10.0.0.5", "nest-hub", NameSourceARP)
	name, src := r.LookupHostnameQuick("10.0.0.5")
	if name != "nest-hub" || src != NameSourceARP {
		t.Fatalf("got %q %q", name, src)
	}
}
