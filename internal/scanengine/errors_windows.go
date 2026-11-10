package scanengine

import (
	"errors"
	"syscall"
)

// Эти коды Winsock и Win32 не экспортируются стандартным пакетом syscall.
const (
	wsaConnectionRefused  syscall.Errno = 10061
	wsaNetworkUnreachable syscall.Errno = 10051
	wsaHostUnreachable    syscall.Errno = 10065
	wsaTimedOut           syscall.Errno = 10060
	winConnectionRefused  syscall.Errno = 1225
	winNetworkUnreachable syscall.Errno = 1231
	winHostUnreachable    syscall.Errno = 1232
	winSemaphoreTimeout   syscall.Errno = 121
)

func platformErrorState(err error) State {
	switch {
	case errors.Is(err, wsaConnectionRefused), errors.Is(err, winConnectionRefused):
		return StateClosed
	case errors.Is(err, wsaNetworkUnreachable), errors.Is(err, wsaHostUnreachable), errors.Is(err, winNetworkUnreachable), errors.Is(err, winHostUnreachable):
		return StateUnreachable
	case errors.Is(err, wsaTimedOut), errors.Is(err, winSemaphoreTimeout):
		return StateTimeout
	default:
		return StateError
	}
}
