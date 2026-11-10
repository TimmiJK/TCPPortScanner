package scanengine

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func classifyError(err error) State {
	switch {
	case errors.Is(err, context.Canceled):
		return StateCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return StateTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return StateUnreachable
	}

	if state := platformErrorState(err); state != StateError {
		return state
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}

	return StateError
}
