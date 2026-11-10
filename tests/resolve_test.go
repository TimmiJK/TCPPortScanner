package tests

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"tcp-scanner/portscan"
)

func TestHostDeduplication(t *testing.T) {
	scanner := newTestScanner(t, 2)

	var closed, lookups atomic.Int32
	scanner.dial = successfulDial(&closed)
	scanner.lookup = func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)

		return []net.IP{net.ParseIP("127.0.0.2")}, nil
	}

	results := scanAll(t, scanner.Scanner, []string{
		" 127.0.0.1 ", "::ffff:127.0.0.1", "::1", "0:0:0:0:0:0:0:1",
		"Example.COM", "example.com", "example.com.", "localhost",
	}, portscan.Range(80, 80))
	seen := make(map[string]net.IP)
	for _, result := range results {
		seen[result.Host] = result.IP
	}

	if len(results) != 4 || lookups.Load() != 2 || !seen["127.0.0.1"].Equal(net.ParseIP("127.0.0.1")) || !seen["::1"].Equal(net.ParseIP("::1")) || seen["Example.COM"] == nil {
		t.Fatalf("результаты=%v DNS-запросов=%d", results, lookups.Load())
	}
}

func TestHostBoundaries(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	valid := []string{"a", "localhost", "a-b.example", "xn--e1afmkfd.xn--p1ai", strings.Repeat("a", 63), maxName, maxName + ".", "127.0.0.1", "::", "2001:db8::1"}
	for _, host := range valid {
		t.Run("valid_"+host, func(t *testing.T) {
			scanner := newTestScanner(t, 1)

			var closed atomic.Int32
			scanner.dial = successfulDial(&closed)
			scanner.lookup = func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}

			results := scanAll(t, scanner.Scanner, []string{host}, portscan.Range(1, 1))
			if len(results) != 1 || results[0].State != portscan.StateOpen {
				t.Fatalf("результаты=%+v", results)
			}
		})
	}

	invalid := []string{"", " ", "\t\n", ".", "..", "999.1.1.1", "127.0.0", "01.2.3.4", "https://example.com", "example.com:443",
		"[::1]", "fe80::1%eth0", "2001:db8:::1", "10.0.0.0/24", "bad..name", "-bad.example", "bad-.example",
		"bad_name", "имя.рф", "bad name", "bad\nname", "name..", strings.Repeat("a", 64), maxName + "e"}
	for _, host := range invalid {
		t.Run("invalid_"+host, func(t *testing.T) {
			scanner := newTestScanner(t, 1)
			results, err := scanner.Scan(testContext(t), []string{host}, portscan.Range(80, 80))
			if err == nil || results != nil {
				t.Fatalf("принят хост %q", host)
			}
		})
	}
}

func TestDNSResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer []net.IP
		want   int
	}{
		{"duplicates", []net.IP{net.ParseIP("127.0.0.1"), {127, 0, 0, 1}, net.ParseIP("::1")}, 2},
		{"empty", nil, 0}, {"nil_ip", []net.IP{nil}, 0},
		{"invalid_ip", []net.IP{[]byte("invalid")}, 0},
		{"valid_then_invalid", []net.IP{net.ParseIP("127.0.0.1"), nil}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := newTestScanner(t, 1)

			var closed atomic.Int32
			scanner.dial = successfulDial(&closed)
			scanner.lookup = func(context.Context, string, string) ([]net.IP, error) { return tc.answer, nil }
			results := scanAll(t, scanner.Scanner, []string{"example.test"}, portscan.Range(80, 80))
			if tc.want == 0 {
				if len(results) != 1 || results[0].State != portscan.StateError || results[0].Err == nil || results[0].IP != nil || results[0].Port != 0 || results[0].Duration != 0 || closed.Load() != 0 {
					t.Fatalf("результаты=%+v", results)
				}
			} else if len(results) != tc.want || int(closed.Load()) != tc.want {
				t.Fatalf("результаты=%+v", results)
			}
		})
	}
}

func TestDNSErrorStatesAndLiteralBypass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		state portscan.State
	}{
		{"not_found", &net.DNSError{Name: "missing.test", IsNotFound: true}, portscan.StateError},
		{"timeout", &net.DNSError{IsTimeout: true}, portscan.StateTimeout},
		{"canceled", context.Canceled, portscan.StateCanceled},
		{"deadline", context.DeadlineExceeded, portscan.StateTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := newTestScanner(t, 1)

			var closed, lookups atomic.Int32
			scanner.dial = successfulDial(&closed)
			scanner.lookup = func(context.Context, string, string) ([]net.IP, error) { lookups.Add(1); return nil, tc.cause }
			results := scanAll(t, scanner.Scanner, []string{"missing.test", "127.0.0.1"}, portscan.Range(80, 80))
			if len(results) != 2 || lookups.Load() != 1 || closed.Load() != 1 {
				t.Fatalf("результаты=%+v", results)
			}

			for _, result := range results {
				if result.Host == "missing.test" && (!errors.Is(result.Err, tc.cause) || result.State != tc.state || result.IP != nil || result.Port != 0) {
					t.Fatalf("результат DNS=%+v", result)
				}
			}
		})
	}
}
