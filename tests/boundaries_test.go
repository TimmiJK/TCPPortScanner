package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tcp-scanner/portscan"
)

func TestNilAndZeroScanners(t *testing.T) {
	var nilScanner *portscan.Scanner
	for _, scanner := range []*portscan.Scanner{nilScanner, new(portscan.Scanner)} {
		results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(80, 80))
		if results != nil || err == nil {
			t.Fatal("неинициализированный сканер принят")
		}

		result := scanner.CheckPort(context.Background(), "test", net.ParseIP("127.0.0.1"), 80)
		if result.State != portscan.StateError || result.Err == nil || result.Duration != 0 {
			t.Fatalf("результат=%+v", result)
		}
	}
}

func TestContextsBeforeNetworkOperations(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()

	for _, tc := range []struct {
		name  string
		ctx   context.Context
		state portscan.State
		cause error
	}{
		{"nil", nil, portscan.StateError, nil},
		{"canceled", canceled, portscan.StateCanceled, context.Canceled},
		{"expired", expired, portscan.StateTimeout, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := newTestScanner(t, 1)
			var called atomic.Int32
			scanner.dial = successfulDial(&called)
			scanner.lookup = func(context.Context, string, string) ([]net.IP, error) {
				called.Add(1)
				return nil, errors.New("неожиданный DNS-запрос")
			}

			results, err := scanner.Scan(tc.ctx, []string{"example.test"}, portscan.Range(80, 80))
			if results != nil || err == nil {
				t.Fatal("некорректный контекст принят")
			}

			result := scanner.CheckPort(tc.ctx, "test", net.ParseIP("127.0.0.1"), 80)
			if result.State != tc.state || result.Err == nil || result.Duration != 0 || called.Load() != 0 {
				t.Fatalf("результат=%+v вызовов=%d", result, called.Load())
			}

			if tc.cause != nil && (!errors.Is(err, tc.cause) || !errors.Is(result.Err, tc.cause)) {
				t.Fatalf("потеряна причина ошибки: %v / %v", err, result.Err)
			}
		})
	}
}

func TestIPByteLengths(t *testing.T) {
	scanner := newTestScanner(t, 1)
	var closed atomic.Int32
	scanner.dial = successfulDial(&closed)
	for _, length := range []int{0, 1, 3, 5, 15, 17, 32} {
		result := scanner.CheckPort(testContext(t), "invalid", make(net.IP, length), 80)
		if result.State != portscan.StateError || result.Err == nil || closed.Load() != 0 {
			t.Fatalf("принят IP длины %d: %+v", length, result)
		}
	}

	for _, ip := range []net.IP{{127, 0, 0, 1}, net.ParseIP("127.0.0.1"), net.ParseIP("2001:db8::1")} {
		for _, port := range []uint16{1, 65535} {
			result := scanner.CheckPort(testContext(t), "valid", ip, port)
			if result.State != portscan.StateOpen || result.Err != nil || result.Port != port || !result.IP.Equal(ip) {
				t.Fatalf("результат=%+v", result)
			}
		}
	}
}

func TestCheckPortFormatsAddressesAndCopiesIP(t *testing.T) {
	for _, tc := range []struct {
		ip      string
		address string
	}{
		{"127.0.0.1", "127.0.0.1:65535"}, {"2001:db8::1", "[2001:db8::1]:65535"},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			scanner := newTestScanner(t, 1)
			var closed atomic.Int32
			scanner.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != tc.address {
					return nil, fmt.Errorf("неверный адрес: %s %s", network, address)
				}

				return &trackedConn{closed: &closed}, nil
			}

			ip := net.ParseIP(tc.ip)
			result := scanner.CheckPort(testContext(t), "метка", ip, 65535)
			if result.State != portscan.StateOpen || result.Host != "метка" || closed.Load() != 1 {
				t.Fatalf("результат=%+v", result)
			}

			ip[0] ^= 0xff
			if !result.IP.Equal(net.ParseIP(tc.ip)) {
				t.Fatal("результат разделяет память с входным IP")
			}
		})
	}
}

type closeFailureConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *closeFailureConn) Close() error {
	c.closed.Add(1)
	return errors.New("ошибка закрытия")
}

func TestCloseErrorPreservesOpen(t *testing.T) {
	scanner := newTestScanner(t, 1)
	conn := &closeFailureConn{}
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	}

	result := scanner.CheckPort(testContext(t), "test", net.ParseIP("127.0.0.1"), 80)
	if result.State != portscan.StateOpen || result.Err != nil || conn.closed.Load() != 1 {
		t.Fatalf("результат=%+v закрытий=%d", result, conn.closed.Load())
	}

	assertReusable(t, scanner)
}

func TestCancelOneScanPreservesAnother(t *testing.T) {
	scanner := newTestScanner(t, 1)

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()

	entered := make(chan struct{})
	var closed atomic.Int32
	scanner.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "127.0.0.1:80" {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}

		return &trackedConn{closed: &closed}, nil
	}

	first, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(80, 80))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("первое подключение не началось")
	}

	second, err := scanner.Scan(testContext(t), []string{"127.0.0.2"}, portscan.Range(80, 82))
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	collect(t, first)
	results := collect(t, second)
	if len(results) != 3 || closed.Load() != 3 {
		t.Fatalf("результаты=%+v", results)
	}

	for _, result := range results {
		if result.State != portscan.StateOpen {
			t.Fatalf("второе сканирование прервано: %+v", result)
		}
	}
}

func TestCancelWhileWaitingForSlot(t *testing.T) {
	scanner := newTestScanner(t, 1)
	ctx := testContext(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	var calls, closed atomic.Int32
	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		close(entered)

		select {
		case <-release:
			return &trackedConn{closed: &closed}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	firstCtx, stopFirst := context.WithCancel(ctx)
	defer stopFirst()

	first := make(chan portscan.Result, 1)
	go func() {
		first <- scanner.CheckPort(firstCtx, "first", net.ParseIP("127.0.0.1"), 80)
	}()

	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("слот не занят")
	}

	waitingCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	result := scanner.CheckPort(waitingCtx, "waiting", net.ParseIP("127.0.0.2"), 80)
	if result.State != portscan.StateTimeout || result.Duration != 0 || !errors.Is(result.Err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("ожидание слота: %+v вызовов=%d", result, calls.Load())
	}

	stopFirst()

	select {
	case <-first:
	case <-ctx.Done():
		t.Fatal("первое подключение не завершилось")
	}

	assertReusable(t, scanner)
}

func TestManyHosts(t *testing.T) {
	scanner := newTestScanner(t, 4)
	var closed atomic.Int32
	scanner.dial = successfulDial(&closed)
	hosts := make([]string, 1000)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}

	results := scanAll(t, scanner.Scanner, hosts, portscan.Range(1, 10))
	seen := make(map[string]bool, len(results))
	for _, result := range results {
		key := fmt.Sprintf("%s:%d", result.Host, result.Port)
		if seen[key] || result.State != portscan.StateOpen {
			t.Fatalf("неверный результат: %+v", result)
		}

		seen[key] = true
	}

	if len(results) != 10000 || closed.Load() != 10000 {
		t.Fatalf("результатов=%d закрыто=%d", len(results), closed.Load())
	}
}
