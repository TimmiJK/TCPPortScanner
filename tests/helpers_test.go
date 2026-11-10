package tests

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tcp-scanner/internal/scanengine"
	"tcp-scanner/portscan"
)

// testScanner позволяет задать сетевые ответы до начала проверки.
// Подстановки меняются только после завершения всех предыдущих вызовов сканера.
type testScanner struct {
	*portscan.Scanner
	dial   func(context.Context, string, string) (net.Conn, error)
	lookup func(context.Context, string, string) ([]net.IP, error)
}

func newTestScanner(t *testing.T, concurrency int) *testScanner {
	t.Helper()

	dialer := &net.Dialer{Timeout: time.Second}
	resolver := &net.Resolver{}
	scanner := &testScanner{dial: dialer.DialContext, lookup: resolver.LookupIP}
	implementation, err := scanengine.New(concurrency, time.Second, scanengine.Dependencies{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return scanner.dial(ctx, network, address)
		},
		Lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return scanner.lookup(ctx, network, host)
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	scanner.Scanner = implementation

	return scanner
}

func successfulDial(closed *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		return &trackedConn{closed: closed}, nil
	}
}

func scanAll(t *testing.T, scanner *portscan.Scanner, hosts []string, ranges ...portscan.PortRange) []portscan.Result {
	t.Helper()

	results, err := scanner.Scan(testContext(t), hosts, ranges...)
	if err != nil {
		t.Fatal(err)
	}

	return collect(t, results)
}

func assertReusable(t *testing.T, scanner *testScanner) {
	t.Helper()

	var closed atomic.Int32
	scanner.dial = successfulDial(&closed)
	results := scanAll(t, scanner.Scanner, []string{"127.0.0.1"}, portscan.Range(80, 80))
	if len(results) != 1 || results[0].State != portscan.StateOpen || closed.Load() != 1 {
		t.Fatalf("сканер не восстановился после отмены: %+v", results)
	}
}

func checkError(t *testing.T, cause error) portscan.Result {
	t.Helper()

	scanner := newTestScanner(t, 1)
	scanner.dial = func(context.Context, string, string) (net.Conn, error) { return nil, cause }

	return scanner.CheckPort(testContext(t), "test", net.ParseIP("127.0.0.1"), 80)
}
