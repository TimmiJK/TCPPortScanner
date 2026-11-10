package tests

import (
	"fmt"
	"syscall"
	"tcp-scanner/portscan"
	"testing"
)

func TestWindowsErrors(t *testing.T) {
	cases := []struct {
		code syscall.Errno
		want portscan.State
	}{
		{10061, portscan.StateClosed}, {1225, portscan.StateClosed},
		{10051, portscan.StateUnreachable}, {10065, portscan.StateUnreachable},
		{1231, portscan.StateUnreachable}, {1232, portscan.StateUnreachable},
		{10060, portscan.StateTimeout}, {121, portscan.StateTimeout}, {5, portscan.StateError},
	}

	for _, tc := range cases {
		if got := checkError(t, fmt.Errorf("wrapped: %w", tc.code)).State; got != tc.want {
			t.Errorf("code %d: got %s want %s", tc.code, got, tc.want)
		}
	}
}
