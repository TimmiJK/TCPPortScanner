package scanengine

import (
	"fmt"
	"slices"
)

// PortRange задаёт включительный диапазон. Равные границы задают один порт.
// Scan проверяет обе границы до преобразования в uint16.
type PortRange struct {
	From int
	To   int
}

// Range задаёт включительный диапазон, который проверяется при вызове Scan.
func Range(from, to int) PortRange {
	return PortRange{From: from, To: to}
}

func normalizePorts(ranges []PortRange) ([]uint16, error) {
	if len(ranges) == 0 {
		return nil, fmt.Errorf("at least one port or range is required")
	}

	intervals := slices.Clone(ranges)
	for _, interval := range intervals {
		if interval.From < 1 || interval.To > 65535 || interval.From > interval.To {
			return nil, fmt.Errorf("invalid port range %d..%d: require 1 <= from <= to <= 65535", interval.From, interval.To)
		}
	}

	slices.SortFunc(intervals, func(a, b PortRange) int { return a.From - b.From })
	ports := make([]uint16, 0)
	last := 0
	for _, interval := range intervals {
		for port := max(interval.From, last+1); port <= interval.To; port++ {
			ports = append(ports, uint16(port))
		}
		last = max(last, interval.To)
	}

	return ports, nil
}
