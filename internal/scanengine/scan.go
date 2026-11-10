// Пакет scanengine выполняет TCP Connect-сканирование с ограничением конкурентности и отменой.
package scanengine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Scanner безопасен для конкурентного использования. Создавайте его через New.
// Лимит подключений общий для всех вызовов Scan и CheckPort одного экземпляра.
type Scanner struct {
	concurrency int
	slots       chan struct{}
	dial        func(context.Context, string, string) (net.Conn, error)
	lookup      func(context.Context, string, string) ([]net.IP, error)
}

// New создаёт сканер с положительными лимитом подключений и таймаутом.
// DNS и ожидание свободного слота ограничиваются контекстом вызывающего кода.
func New(concurrency int, connectTimeout time.Duration, dependencies Dependencies) (*Scanner, error) {
	if concurrency <= 0 {
		return nil, fmt.Errorf("concurrency must be positive: %d", concurrency)
	}
	if connectTimeout <= 0 {
		return nil, fmt.Errorf("connect timeout must be positive: %s", connectTimeout)
	}

	dialer := &net.Dialer{Timeout: connectTimeout}
	resolver := &net.Resolver{}
	if dependencies.Dial == nil {
		dependencies.Dial = dialer.DialContext
	}
	if dependencies.Lookup == nil {
		dependencies.Lookup = resolver.LookupIP
	}

	return &Scanner{
		concurrency: concurrency,
		slots:       make(chan struct{}, concurrency),
		dial:        dependencies.Dial,
		lookup:      dependencies.Lookup,
	}, nil
}

// Dependencies задаёт сетевые операции для внутренней реализации и тестов.
// Нулевые поля заменяются стандартными операциями Go. Функции должны учитывать контекст.
type Dependencies struct {
	Dial   func(context.Context, string, string) (net.Conn, error)
	Lookup func(context.Context, string, string) ([]net.IP, error)
}

func (s *Scanner) validate(ctx context.Context) error {
	if s == nil || s.slots == nil {
		return fmt.Errorf("scanner must be created with New")
	}
	if ctx == nil {
		return fmt.Errorf("context must not be nil")
	}

	return ctx.Err()
}

// CheckPort проверяет один IP и порт с учётом общего лимита подключений сканера.
// Host копируется в результат как метка. Duration измеряет только попытку подключения.
func (s *Scanner) CheckPort(ctx context.Context, host string, ip net.IP, port uint16) Result {
	result := Result{Host: host, IP: append(net.IP(nil), ip...), Port: port}

	if err := s.validate(ctx); err != nil {
		result.Err = err
		result.State = classifyError(err)
		return result
	}

	if ip.To16() == nil || port == 0 {
		result.Err = fmt.Errorf("a valid IP and a port in 1..65535 are required")
		result.State = StateError
		return result
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		result.Err = ctx.Err()
		result.State = classifyError(result.Err)
		return result
	}

	if err := ctx.Err(); err != nil {
		result.Err = err
		result.State = classifyError(err)
		return result
	}

	address := net.JoinHostPort(result.IP.String(), strconv.Itoa(int(port)))
	started := time.Now()
	conn, err := s.dial(ctx, "tcp", address)
	result.Duration = time.Since(started)
	if err != nil {
		result.Err = fmt.Errorf("connect %s: %w", address, err)
		result.State = classifyError(err)
		return result
	}

	_ = conn.Close()
	result.State = StateOpen

	return result
}

type scanJob struct {
	host string
	ip   net.IP
	port uint16
}

// Scan проверяет входные данные до запуска горутин и возвращает результаты по мере готовности.
// Для каждой уникальной пары IP и порта возвращается результат с исходным хостом.
// При ошибке DNS поля IP=nil и Port=0. После отмены часть результатов может быть отброшена.
// Если чтение завершено досрочно, вызывающий код должен отменить ctx для освобождения воркеров.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ranges ...PortRange) (<-chan Result, error) {
	if err := s.validate(ctx); err != nil {
		return nil, err
	}

	targets, err := normalizeHosts(hosts)
	if err != nil {
		return nil, err
	}

	ports, err := normalizePorts(ranges)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	jobs := make(chan scanJob, s.concurrency)
	results := make(chan Result, s.concurrency)
	var workers sync.WaitGroup

	workers.Add(s.concurrency + 1)
	go func() {
		defer workers.Done()
		defer close(jobs)
		s.produce(ctx, targets, ports, jobs, results)
	}()

	for i := 0; i < s.concurrency; i++ {
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}

				result := s.CheckPort(ctx, job.host, job.ip, job.port)
				if !sendResult(ctx, results, result) {
					return
				}
			}
		}()
	}

	go func() {
		workers.Wait()
		close(results)
	}()

	return results, nil
}

func (s *Scanner) produce(ctx context.Context, targets []target, ports []uint16, jobs chan<- scanJob, results chan<- Result) {
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}

		ips, err := s.resolve(ctx, target)
		if err != nil {
			result := Result{Host: target.host, State: classifyError(err), Err: err}
			if !sendResult(ctx, results, result) {
				return
			}
			continue
		}

		for _, ip := range ips {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}

				select {
				case jobs <- scanJob{host: target.host, ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func sendResult(ctx context.Context, results chan<- Result, result Result) bool {
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}
