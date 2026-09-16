// Command package-checker-lsp is the language server behind the Zed
// package-checker extension.
//
// It speaks LSP over stdio and reports vulnerable and malicious dependencies as
// diagnostics. Zed launches it; it is not intended to be run interactively,
// though --version and --help work for diagnosis.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.lsp.dev/jsonrpc2"
	"go.lsp.dev/protocol"

	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/lsp"
)

// version is overridden at build time via
// -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "package-checker-lsp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		logPath     = flag.String("log", "", "also write logs to this file")
	)
	flag.Bool("stdio", true, "communicate over stdio (default, accepted for compatibility)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log, closeLog, err := newLogger(*logPath)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	defer closeLog()

	// SIGINT/SIGTERM cancel the root context, which closes the connection and
	// unwinds every goroutine that derives from it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version)

	// scalibr keeps its logger in a package global and writes unstructured
	// lines to stderr by default, which would land in the editor's LSP log
	// alongside ours.
	extract.SetLogger(log)

	extractor, err := extract.New()
	if err != nil {
		return fmt.Errorf("configure extraction: %w", err)
	}

	// The server and the client handle are mutually dependent: NewServer needs
	// the server to build the connection, and the server needs the resulting
	// client to push diagnostics. Construct first, inject second.
	srv := lsp.NewServer(log, version, extractor)
	stream := jsonrpc2.NewStream(stdio{})
	ctx, conn, client := protocol.NewServer(ctx, srv, stream)
	srv.SetClient(client)

	<-conn.Done()

	if err := conn.Err(); err != nil {
		return fmt.Errorf("connection closed: %w", err)
	}
	log.Info("connection closed cleanly")
	return nil
}

// newLogger builds a logger that never writes to stdout, plus a function to
// release any file it opened.
//
// stdout carries the JSON-RPC stream; a single stray byte there corrupts the
// protocol. Logs go to stderr, which Zed surfaces in its LSP log, and
// optionally to a file as well for debugging.
func newLogger(path string) (*slog.Logger, func(), error) {
	var (
		out   io.Writer = os.Stderr
		close           = func() {}
	)
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
		}
		out = io.MultiWriter(os.Stderr, f)
		close = func() { _ = f.Close() }
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})), close, nil
}

// stdio adapts the process's standard streams to a single io.ReadWriteCloser
// for the JSON-RPC transport.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error {
	if err := os.Stdin.Close(); err != nil {
		return err
	}
	return os.Stdout.Close()
}
