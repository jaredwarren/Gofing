package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

func inspectTLSCert(cert *x509.Certificate, port int) *TLSInfo {
	if cert == nil {
		return nil
	}
	info := &TLSInfo{
		Port:      port,
		SubjectCN: cert.Subject.CommonName,
		SANs:      cert.DNSNames,
	}
	if len(cert.Issuer.Organization) > 0 {
		info.IssuerOrg = strings.Join(cert.Issuer.Organization, ", ")
	}
	return info
}

func probeTLS(ctx context.Context, ip string, candidatePorts []int) (*TLSInfo, error) {
	ports := candidatePorts
	if len(ports) == 0 {
		ports = []int{443, 8443}
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		dialer := &net.Dialer{
			Timeout: 800 * time.Millisecond,
		}
		target := fmt.Sprintf("%s:%d", ip, port)

		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			continue
		}

		state := conn.ConnectionState()
		_ = conn.Close()

		if len(state.PeerCertificates) > 0 {
			info := inspectTLSCert(state.PeerCertificates[0], port)
			if info != nil && (info.SubjectCN != "" || len(info.SANs) > 0) {
				return info, nil
			}
		}
	}

	return nil, fmt.Errorf("no tls certificates resolved on candidate ports")
}
