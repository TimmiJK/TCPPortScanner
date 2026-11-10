package tests

import (
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"tcp-scanner/portscan"
)

func TestPortRangesAndInputOwnership(t *testing.T) {
	scanner := newTestScanner(t, 4)

	var closed atomic.Int32
	scanner.dial = successfulDial(&closed)
	input := []portscan.PortRange{portscan.Range(80, 82), portscan.Range(22, 22), portscan.Range(81, 84), portscan.Range(65535, 65535), portscan.Range(80, 80)}
	original := slices.Clone(input)
	results := scanAll(t, scanner.Scanner, []string{"127.0.0.1"}, input...)
	ports := make([]uint16, 0, len(results))
	for _, result := range results {
		ports = append(ports, result.Port)
	}

	slices.Sort(ports)
	want := []uint16{22, 80, 81, 82, 83, 84, 65535}
	if !reflect.DeepEqual(ports, want) || !reflect.DeepEqual(input, original) || int(closed.Load()) != len(want) {
		t.Fatalf("порты=%v исходные диапазоны=%v закрыто=%d", ports, input, closed.Load())
	}
}

func TestFullPortRange(t *testing.T) {
	scanner := newTestScanner(t, 8)

	var closed atomic.Int32
	scanner.dial = successfulDial(&closed)
	results := scanAll(t, scanner.Scanner, []string{"127.0.0.1"}, portscan.Range(1, 65535), portscan.Range(1, 65535))
	seen := make(map[uint16]bool, 65535)
	for _, result := range results {
		if result.Port == 0 || seen[result.Port] || result.State != portscan.StateOpen {
			t.Fatalf("неверный результат: %+v", result)
		}
		seen[result.Port] = true
	}

	if len(seen) != 65535 || !seen[1] || !seen[65535] || closed.Load() != 65535 {
		t.Fatalf("проверено=%d закрыто=%d", len(seen), closed.Load())
	}
}

func TestInvalidPorts(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	cases := []struct {
		name   string
		ranges []portscan.PortRange
	}{
		{"empty", nil},
		{"zero", []portscan.PortRange{portscan.Range(0, 0)}},
		{"negative", []portscan.PortRange{portscan.Range(-1, 80)}},
		{"negative_end", []portscan.PortRange{portscan.Range(1, -1)}},
		{"too_large_end", []portscan.PortRange{portscan.Range(1, 65536)}},
		{"too_large_start", []portscan.PortRange{portscan.Range(65536, 65536)}},
		{"reversed", []portscan.PortRange{portscan.Range(1000, 1)}},
		{"invalid_after_valid", []portscan.PortRange{portscan.Range(80, 80), portscan.Range(0, 0)}},
		{"max_int", []portscan.PortRange{portscan.Range(maxInt, maxInt)}},
		{"min_int", []portscan.PortRange{portscan.Range(-maxInt-1, 80)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := newTestScanner(t, 1)

			var calls atomic.Int32
			scanner.dial = successfulDial(&calls)
			results, err := scanner.Scan(testContext(t), []string{"127.0.0.1"}, tc.ranges...)
			if err == nil || results != nil || calls.Load() != 0 {
				t.Fatalf("приняты диапазоны %v: %v", tc.ranges, err)
			}
		})
	}
}
