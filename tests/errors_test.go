package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"tcp-scanner/portscan"
	"testing"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		err  error
		want portscan.State
	}{
		{context.Canceled, portscan.StateCanceled},
		{context.DeadlineExceeded, portscan.StateTimeout},
		{syscall.ECONNREFUSED, portscan.StateClosed},
		{syscall.ENETUNREACH, portscan.StateUnreachable},
		{syscall.EHOSTUNREACH, portscan.StateUnreachable},
		{syscall.ETIMEDOUT, portscan.StateTimeout},
		{&net.DNSError{IsTimeout: true}, portscan.StateTimeout},
		{&net.DNSError{IsNotFound: true}, portscan.StateError},
		{errors.New("connection refused"), portscan.StateError},
		{errors.New("i/o timeout"), portscan.StateError},
	}

	for _, tc := range cases {
		wrapped := fmt.Errorf("outer: %w", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: tc.err}})
		result := checkError(t, wrapped)
		if result.State != tc.want || !errors.Is(result.Err, tc.err) {
			t.Errorf("%v: состояние=%s ожидалось=%s ошибка=%v", tc.err, result.State, tc.want, result.Err)
		}
	}
}
