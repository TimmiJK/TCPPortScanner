package scanengine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type target struct {
	host string
	ip   net.IP
}

func normalizeHosts(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("at least one host is required")
	}

	targets := make([]target, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		entry := target{host: host}
		key := strings.ToLower(strings.TrimSuffix(host, "."))
		if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
			ip = ip.Unmap()
			entry.ip = net.IP(ip.AsSlice())
			key = ip.String()
		} else if !validDNSName(host) {
			return nil, fmt.Errorf("invalid host %q: expected an IP address or DNS hostname", raw)
		}

		if !seen[key] {
			targets = append(targets, entry)
			seen[key] = true
		}
	}

	return targets, nil
}

func validDNSName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}

	if strings.Contains(name, ".") && strings.Trim(name, "0123456789.") == "" {
		return false
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}

	return true
}

func (s *Scanner) resolve(ctx context.Context, target target) ([]net.IP, error) {
	if target.ip != nil {
		return []net.IP{target.ip}, nil
	}

	ips, err := s.lookup(ctx, "ip", target.host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", target.host, err)
	}

	unique := make([]net.IP, 0, len(ips))
	seen := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("resolve %q: invalid IP in DNS response", target.host)
		}

		address = address.Unmap()
		if !seen[address] {
			unique = append(unique, net.IP(address.AsSlice()))
			seen[address] = true
		}
	}

	if len(unique) == 0 {
		return nil, fmt.Errorf("resolve %q: no IP addresses", target.host)
	}

	return unique, nil
}
