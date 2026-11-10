package tests

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"tcp-scanner/portscan"
)

func TestSlowConsumerResumesWithoutLostResults(t *testing.T) {
	scanner := newTestScanner(t, 2)
	ctx := testContext(t)
	started := make(chan struct{}, 100)
	var closed atomic.Int32
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		started <- struct{}{}
		return &trackedConn{closed: &closed}, nil
	}

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 100))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("воркеры не заполнили буфер результатов")
		}
	}

	select {
	case <-started:
		t.Fatal("число подключений превысило объём ожидающих результатов")
	default:
	}

	all := collect(t, results)
	seen := make(map[uint16]bool)
	for _, result := range all {
		if result.State != portscan.StateOpen || seen[result.Port] {
			t.Fatalf("неверный результат: %+v", result)
		}

		seen[result.Port] = true
	}

	if len(all) != 100 || closed.Load() != 100 {
		t.Fatalf("результатов=%d закрыто=%d", len(all), closed.Load())
	}
}
