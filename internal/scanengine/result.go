package scanengine

import (
	"net"
	"time"
)

// State описывает исход одной попытки подключения.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

// Result содержит результат подключения или ошибку разрешения имени хоста.
// При ошибке разрешения имени IP равен nil, а Port и Duration равны нулю.
// Err сохраняет исходную причину для errors.Is и errors.As.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
