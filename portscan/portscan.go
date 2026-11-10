// Пакет portscan выполняет TCP Connect-сканирование с ограничением конкурентности и отменой.
package portscan

import (
	"time"

	"tcp-scanner/internal/scanengine"
)

// Scanner безопасен для конкурентного использования. Создавайте его через New.
// Лимит подключений общий для всех вызовов Scan и CheckPort одного экземпляра.
type Scanner = scanengine.Scanner

// State описывает состояние проверенного порта.
type State = scanengine.State

const (
	StateOpen        = scanengine.StateOpen
	StateClosed      = scanengine.StateClosed
	StateTimeout     = scanengine.StateTimeout
	StateUnreachable = scanengine.StateUnreachable
	StateCanceled    = scanengine.StateCanceled
	StateError       = scanengine.StateError
)

// Result содержит результат подключения или ошибку разрешения имени хоста.
type Result = scanengine.Result

// PortRange задаёт включительный диапазон портов. Равные границы задают один порт.
type PortRange = scanengine.PortRange

// New создаёт сканер с положительными лимитом подключений и таймаутом.
// DNS и ожидание свободного слота ограничиваются контекстом вызывающего кода.
func New(concurrency int, connectTimeout time.Duration) (*Scanner, error) {
	return scanengine.New(concurrency, connectTimeout, scanengine.Dependencies{})
}

// Range задаёт включительный диапазон. Границы проверяются при вызове Scan.
func Range(from, to int) PortRange {
	return scanengine.Range(from, to)
}
