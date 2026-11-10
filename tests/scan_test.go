package tests

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"tcp-scanner/portscan"
	"testing"
	"time"
)

func testContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	return ctx
}

func collect(t *testing.T, results <-chan portscan.Result) []portscan.Result {
	t.Helper()

	var all []portscan.Result
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				return all
			}

			all = append(all, result)
		case <-timer.C:
			t.Fatal("results channel did not close")
		}
	}
}

type trackedConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c *trackedConn) Close() error {
	c.closed.Add(1)
	return nil
}

func TestNewAndInputValidation(t *testing.T) {
	for _, tc := range []struct {
		n       int
		timeout time.Duration
	}{
		{0, time.Second},
		{-1, time.Second},
		{1, 0},
		{1, -time.Second},
	} {
		if _, err := portscan.New(tc.n, tc.timeout); err == nil {
			t.Errorf("accepted %+v", tc)
		}
	}

	scanner := newTestScanner(t, 1)
	var calls atomic.Int32
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, syscall.ECONNREFUSED
	}

	for _, tc := range []struct {
		hosts []string
		ports []portscan.PortRange
	}{
		{nil, []portscan.PortRange{portscan.Range(80, 80)}},
		{[]string{"127.0.0.1", ""}, []portscan.PortRange{portscan.Range(80, 80)}},
		{[]string{"127.0.0.1"}, nil},
		{[]string{"127.0.0.1"}, []portscan.PortRange{portscan.Range(80, 80), portscan.Range(0, 0)}},
	} {
		results, err := scanner.Scan(testContext(t), tc.hosts, tc.ports...)
		if err == nil || results != nil {
			t.Fatalf("invalid input started scan: %+v", tc)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(80, 80)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}

	if _, err := scanner.Scan(nil, []string{"127.0.0.1"}, portscan.Range(80, 80)); err == nil {
		t.Error("accepted nil context")
	}

	var zero portscan.Scanner
	if _, err := zero.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(80, 80)); err == nil {
		t.Error("accepted zero scanner")
	}

	for _, tc := range []struct {
		ip   net.IP
		port uint16
	}{
		{nil, 80},
		{[]byte("127.0.0.1"), 80},
		{net.ParseIP("127.0.0.1"), 0},
	} {
		if result := scanner.CheckPort(context.Background(), "test", tc.ip, tc.port); result.State != portscan.StateError || result.Err == nil {
			t.Errorf("invalid check: %+v", result)
		}
	}

	if calls.Load() != 0 {
		t.Fatal("validation performed network calls")
	}
}

func TestScanLocalServer(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "tcp6" {
				host = "::1"
			}

			listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()

			if network == "tcp6" {
				probe, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
				if err != nil {
					t.Skipf("IPv6 loopback connections unavailable: %v", err)
				}

				_ = probe.Close()
				peer, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}

				_ = peer.Close()
			}

			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()

				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				var data [1]byte
				_, err = conn.Read(data[:])
				peerDone <- err
			}()

			port := listener.Addr().(*net.TCPAddr).Port
			scanner, err := portscan.New(2, time.Second)
			if err != nil {
				t.Fatal(err)
			}

			results, err := scanner.Scan(testContext(t), []string{host}, portscan.Range(port, port))
			if err != nil {
				t.Fatal(err)
			}

			all := collect(t, results)
			if len(all) != 1 || all[0].State != portscan.StateOpen || all[0].Err != nil {
				t.Fatalf("results=%+v", all)
			}

			select {
			case err := <-peerDone:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("connection was not closed cleanly: %v", err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("server still waiting")
			}
		})
	}
}

func TestScanDNSAndDeduplication(t *testing.T) {
	scanner := newTestScanner(t, 3)

	var lookups, closed atomic.Int32
	dnsErr := &net.DNSError{Name: "missing.test", IsNotFound: true}
	scanner.lookup = func(_ context.Context, network, host string) ([]net.IP, error) {
		lookups.Add(1)
		if network != "ip" {
			return nil, errors.New("wrong lookup network")
		}

		if host == "missing.test" {
			return nil, dnsErr
		}

		return []net.IP{net.ParseIP("127.0.0.1"), {127, 0, 0, 1}, net.ParseIP("::1")}, nil
	}

	scanner.dial = func(context.Context, string, string) (net.Conn, error) { return &trackedConn{closed: &closed}, nil }
	results, err := scanner.Scan(testContext(t), []string{"example.test", "EXAMPLE.TEST", "missing.test", "127.0.0.1"}, portscan.Range(80, 81), portscan.Range(81, 81))
	if err != nil {
		t.Fatal(err)
	}

	all := collect(t, results)
	if len(all) != 7 || lookups.Load() != 2 || closed.Load() != 6 {
		t.Fatalf("results=%v lookups=%d closed=%d", all, lookups.Load(), closed.Load())
	}

	seen := make(map[string]bool)
	for _, result := range all {
		if result.Host == "missing.test" {
			if !errors.Is(result.Err, dnsErr) || result.State != portscan.StateError || result.IP != nil || result.Port != 0 {
				t.Fatalf("DNS result: %+v", result)
			}
			continue
		}

		key := result.Host + "/" + net.JoinHostPort(result.IP.String(), strconv.Itoa(int(result.Port)))
		if seen[key] || result.State != portscan.StateOpen {
			t.Fatalf("unexpected result: %+v", result)
		}

		seen[key] = true
	}
}

func TestSharedLimitAndReuse(t *testing.T) {
	scanner := newTestScanner(t, 3)

	ctx := testContext(t)
	started := make(chan struct{}, 100)
	release := make(chan struct{})
	var active, peak, closed atomic.Int32
	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		current := active.Add(1)
		defer active.Add(-1)

		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}

		started <- struct{}{}
		select {
		case <-release:
			return &trackedConn{closed: &closed}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	first, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 10))
	if err != nil {
		t.Fatal(err)
	}

	second, err := scanner.Scan(ctx, []string{"::1"}, portscan.Range(1, 10))
	if err != nil {
		t.Fatal(err)
	}

	direct := make(chan portscan.Result, 1)
	go func() {
		direct <- scanner.CheckPort(ctx, "direct", net.ParseIP("127.0.0.1"), 80)
	}()

	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("workers did not start")
		}
	}

	close(release)

	if len(collect(t, first)) != 10 || len(collect(t, second)) != 10 {
		t.Fatal("missing results")
	}

	select {
	case result := <-direct:
		if result.State != portscan.StateOpen {
			t.Fatalf("direct=%+v", result)
		}
	case <-ctx.Done():
		t.Fatal("direct check did not finish")
	}

	third, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(80, 80))
	if err != nil {
		t.Fatal(err)
	}

	if len(collect(t, third)) != 1 || peak.Load() != 3 || active.Load() != 0 || closed.Load() != 22 {
		t.Fatalf("peak=%d active=%d closed=%d", peak.Load(), active.Load(), closed.Load())
	}
}

func TestCancelActiveAndWaitingConnections(t *testing.T) {
	scanner := newTestScanner(t, 1)

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()

	started := make(chan struct{}, 1)
	var calls atomic.Int32
	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()

		return nil, ctx.Err()
	}

	first := make(chan portscan.Result, 1)
	go func() {
		first <- scanner.CheckPort(ctx, "first", net.ParseIP("127.0.0.1"), 80)
	}()

	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("dial did not start")
	}

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 65535))
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	collect(t, results)

	select {
	case result := <-first:
		if result.State != portscan.StateCanceled || !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("result=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("active dial did not stop")
	}

	if calls.Load() != 1 {
		t.Fatal("new dial after cancellation or occupied slot")
	}

	assertReusable(t, scanner)
}

func TestCancelBlockedDNS(t *testing.T) {
	scanner := newTestScanner(t, 2)

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()

	started := make(chan struct{})
	scanner.lookup = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		close(started)
		<-ctx.Done()

		return nil, ctx.Err()
	}

	results, err := scanner.Scan(ctx, []string{"example.test"}, portscan.Range(80, 80))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("DNS did not start")
	}

	cancel()
	collect(t, results)
}

func TestCancelWithoutReadingResults(t *testing.T) {
	scanner := newTestScanner(t, 2)

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()

	var closed atomic.Int32
	started := make(chan struct{}, 10)
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		started <- struct{}{}
		return &trackedConn{closed: &closed}, nil
	}

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 65535))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("backpressure setup failed")
		}
	}

	cancel()

	all := collect(t, results)
	if len(all) > 4 || closed.Load() != 4 {
		t.Fatalf("results=%d closed=%d", len(all), closed.Load())
	}

	assertReusable(t, scanner)
}

func TestCheckPortDeadline(t *testing.T) {
	scanner := newTestScanner(t, 1)

	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(testContext(t), 20*time.Millisecond)
	defer cancel()

	result := scanner.CheckPort(ctx, "deadline", net.ParseIP("127.0.0.1"), 80)
	if result.State != portscan.StateTimeout || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result=%+v", result)
	}

	assertReusable(t, scanner)
}

func TestScanCopiesInputsAndResults(t *testing.T) {
	scanner := newTestScanner(t, 1)

	ctx := testContext(t)
	var closed atomic.Int32
	scanner.dial = func(context.Context, string, string) (net.Conn, error) { return &trackedConn{closed: &closed}, nil }
	hosts := []string{"127.0.0.1"}
	ranges := []portscan.PortRange{portscan.Range(80, 90)}
	results, err := scanner.Scan(ctx, hosts, ranges...)
	if err != nil {
		t.Fatal(err)
	}

	hosts[0] = "changed.test"
	ranges[0] = portscan.Range(0, 0)
	count := 0
	for result := range results {
		if result.Host != "127.0.0.1" || !result.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("result=%+v", result)
		}

		result.IP[0] = 0
		count++
	}

	if count != 11 {
		t.Fatalf("count=%d", count)
	}
}
