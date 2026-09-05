package mdns

import (
	"encoding/binary"
	"testing"
)

func TestParseMDNSARecord(t *testing.T) {
	pkt := buildMDNSAnswers([]testRR{{
		name: "Amys-MBP.local",
		typ:  dnsTypeA,
		data: []byte{192, 168, 0, 142},
	}})
	got := parseMDNSMessage(pkt)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].IP != "192.168.0.142" || got[0].Hostname != "Amys-MBP" {
		t.Fatalf("%+v", got[0])
	}
}

func TestParseMDNSReversePTRPlusA(t *testing.T) {
	pkt := buildMDNSAnswers([]testRR{
		{
			name: "142.0.168.192.in-addr.arpa",
			typ:  dnsTypePTR,
			data: encodeName("Amys-MBP.local"),
		},
		{
			name: "Amys-MBP.local",
			typ:  dnsTypeA,
			data: []byte{192, 168, 0, 142},
		},
	})
	got := parseMDNSMessage(pkt)
	if len(got) != 1 || got[0].Hostname != "Amys-MBP" || got[0].IP != "192.168.0.142" {
		t.Fatalf("%+v", got)
	}
}

func TestParseMDNSSRVUsesTargetNotInstance(t *testing.T) {
	pkt := buildMDNSAnswers([]testRR{
		{
			name: "iPad (73)._companion-link._tcp.local",
			typ:  dnsTypeSRV,
			data: srvRDATA("iPad.local"),
		},
		{
			name: "iPad.local",
			typ:  dnsTypeA,
			data: []byte{192, 168, 0, 51},
		},
	})
	got := parseMDNSMessage(pkt)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].IP != "192.168.0.51" || got[0].Hostname != "iPad" {
		t.Fatalf("want iPad @ .51, got %+v", got[0])
	}
}

func TestParseMDNSIgnoresServiceInstanceAsHostname(t *testing.T) {
	pkt := buildMDNSAnswers([]testRR{{
		name: "_companion-link._tcp.local",
		typ:  dnsTypePTR,
		data: encodeName("iPad (73)._companion-link._tcp.local"),
	}})
	got := parseMDNSMessage(pkt)
	if len(got) != 0 {
		t.Fatalf("instance PTR must not yield a hostname: %+v", got)
	}
}

func TestParseMDNSIgnoresLKDC(t *testing.T) {
	txt := encodeTXT("LKDC:SHA1.6C287FBDDEADBEEF")
	pkt := buildMDNSQueryAndAdds(
		"6C287FBDDEADBEEF.lkdc.apple.com.local",
		[]testRR{{
			name: "LKDC:SHA1.6C287FBDDEADBEEF.local",
			typ:  dnsTypeTXT,
			data: txt,
		}},
	)
	got := parseMDNSMessage(pkt)
	if len(got) != 0 {
		t.Fatalf("LKDC must not yield a hostname: %+v", got)
	}
}

func TestIngestLearnedDoesNotDemoteDHCPCache(t *testing.T) {
	r := New()
	r.rememberIPName("192.168.0.142", "Amys-MBP", NameSourceDHCP)
	r.ingestLearned([]learnedName{{IP: "192.168.0.142", Hostname: "iPad (73)"}})
	name, src := r.CachedName("192.168.0.142")
	if name != "Amys-MBP" || src != NameSourceDHCP {
		t.Fatalf("got %q/%q", name, src)
	}
}

func TestIngestLearnedFiresCallback(t *testing.T) {
	r := New()
	var gotIP, gotHost, gotSrc string
	r.SetNameLearnedHandler(func(ip, hostname, source string) {
		gotIP, gotHost, gotSrc = ip, hostname, source
	})
	r.ingestLearned([]learnedName{{IP: "192.168.0.142", Hostname: "Amys-MBP"}})
	if gotIP != "192.168.0.142" || gotHost != "Amys-MBP" || gotSrc != NameSourceMDNS {
		t.Fatalf("callback %q %q %q", gotIP, gotHost, gotSrc)
	}
}

type testRR struct {
	name string
	typ  uint16
	data []byte
}

func buildMDNSAnswers(rrs []testRR) []byte {
	return buildMDNS(0, rrs)
}

func buildMDNSQueryAndAdds(qname string, adds []testRR) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QD
	binary.BigEndian.PutUint16(msg[10:12], uint16(len(adds)))
	msg = append(msg, encodeName(qname)...)
	msg = append(msg, 0, 12, 0, 1) // PTR IN
	for _, rr := range adds {
		msg = appendRR(msg, rr)
	}
	return msg
}

func buildMDNS(qd uint16, rrs []testRR) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400)
	binary.BigEndian.PutUint16(msg[4:6], qd)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(rrs)))
	for _, rr := range rrs {
		msg = appendRR(msg, rr)
	}
	return msg
}

func appendRR(msg []byte, rr testRR) []byte {
	msg = append(msg, encodeName(rr.name)...)
	tmp := make([]byte, 10)
	binary.BigEndian.PutUint16(tmp[0:2], rr.typ)
	binary.BigEndian.PutUint16(tmp[2:4], 0x8001) // IN + cache flush
	binary.BigEndian.PutUint32(tmp[4:8], 120)
	binary.BigEndian.PutUint16(tmp[8:10], uint16(len(rr.data)))
	msg = append(msg, tmp...)
	return append(msg, rr.data...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range splitDNSLabels(name) {
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out
}

func splitDNSLabels(name string) []string {
	name = trimDot(name)
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func trimDot(name string) string {
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

func srvRDATA(target string) []byte {
	data := make([]byte, 6)
	binary.BigEndian.PutUint16(data[4:6], 7000)
	return append(data, encodeName(target)...)
}

func encodeTXT(s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	return append([]byte{byte(len(s))}, []byte(s)...)
}
