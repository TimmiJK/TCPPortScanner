// Пакет cli содержит обработку аргументов и запуск консольного примера.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"tcp-scanner/portscan"
)

// Run запускает сканирование с отдельным набором флагов и переданными потоками вывода.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("context must not be nil")
	}

	flags := flag.NewFlagSet("portscan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	hosts := flags.String("hosts", "127.0.0.1", "IP-адреса или DNS-имена через запятую")
	ports := flags.String("ports", "80,443", "порты и включительные диапазоны, например 22,80,8000-8010")
	concurrency := flags.Int("concurrency", 100, "максимальное число одновременных подключений")
	timeout := flags.Duration("timeout", time.Second, "таймаут одного TCP-подключения")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}

	ranges, err := ParseRanges(*ports)
	if err != nil {
		return err
	}

	scanner, err := portscan.New(*concurrency, *timeout)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results, err := scanner.Scan(ctx, strings.Split(*hosts, ","), ranges...)
	if err != nil {
		return err
	}

	for result := range results {
		line := fmt.Sprintf("host=%s ip=%v port=%d state=%s duration=%s", result.Host, result.IP, result.Port, result.State, result.Duration)
		if result.Err != nil {
			line += fmt.Sprintf(" error=%q", result.Err)
		}

		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}

	return ctx.Err()
}

// ParseRanges разбирает список портов и диапазонов. Допустимость границ проверяет Scan.
func ParseRanges(input string) ([]portscan.PortRange, error) {
	var ranges []portscan.PortRange
	for _, item := range strings.Split(input, ",") {
		left, right, isRange := strings.Cut(strings.TrimSpace(item), "-")
		from, err := strconv.Atoi(strings.TrimSpace(left))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", item, err)
		}

		to := from
		if isRange {
			to, err = strconv.Atoi(strings.TrimSpace(right))
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", item, err)
			}
		}

		ranges = append(ranges, portscan.Range(from, to))
	}

	return ranges, nil
}
