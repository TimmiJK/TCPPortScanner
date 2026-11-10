package tests

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"tcp-scanner/internal/cli"
	"tcp-scanner/portscan"
)

func TestParseRanges(t *testing.T) {
	got, err := cli.ParseRanges("22, 80, 8000-8002")
	want := []portscan.PortRange{portscan.Range(22, 22), portscan.Range(80, 80), portscan.Range(8000, 8002)}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v err=%v", got, err)
	}

	for _, input := range []string{"", " ", ",80", "80,", "80,,443", "abc", "1-", "-80", "1-2-3", "1.5", "0x50", "80;443", strings.Repeat("9", 100), "1-" + strings.Repeat("9", 100)} {
		if _, err := cli.ParseRanges(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestParseRangesWhitespace(t *testing.T) {
	got, err := cli.ParseRanges(" 1 , 80 - 82 , 65535 ")
	want := []portscan.PortRange{portscan.Range(1, 1), portscan.Range(80, 82), portscan.Range(65535, 65535)}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("диапазоны=%v ошибка=%v", got, err)
	}
}

func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{
		{"-unknown"}, {"-hosts"}, {"unexpected"}, {"-timeout", "five"},
		{"-timeout", "0s"}, {"-timeout", "-1s"}, {"-concurrency", "0"}, {"-concurrency", "-1"},
		{"-concurrency", "abc"}, {"-hosts", ""}, {"-hosts", "127.0.0.1,"},
		{"-hosts", "https://example.com"}, {"-ports", ""}, {"-ports", "0"},
		{"-ports", "65536"}, {"-ports", "80-1"}, {"-ports", "abc"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := cli.Run(testContext(t), args, &stdout, &stderr)
			if err == nil || stdout.Len() != 0 {
				t.Fatalf("аргументы=%v ошибка=%v вывод=%q", args, err, stdout.String())
			}
		})
	}
}

func TestCLIHelpAndContext(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cli.Run(testContext(t), []string{"-h"}, &stdout, &stderr); err != nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "-hosts") {
		t.Fatalf("справка: %v %q", err, stderr.String())
	}

	if err := cli.Run(nil, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("принят nil-контекст")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := cli.Run(ctx, nil, io.Discard, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("ошибка отмены=%v", err)
	}
}

type failingWriter struct{ cause error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.cause }

func TestCLILocalServerAndOutputFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	args := []string{"-hosts", "127.0.0.1", "-ports", port, "-concurrency", "1", "-timeout", "1s"}
	var stdout bytes.Buffer
	if err := cli.Run(testContext(t), args, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout.String(), "port="+port+" state=open") || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("вывод=%q", stdout.String())
	}

	cause := errors.New("вывод недоступен")
	if err := cli.Run(testContext(t), args, failingWriter{cause}, io.Discard); !errors.Is(err, cause) {
		t.Fatalf("ошибка вывода потеряна: %v", err)
	}
}
