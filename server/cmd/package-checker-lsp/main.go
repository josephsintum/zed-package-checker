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

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/engine"
	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/lsp"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
	"github.com/josephsintum/zed-package-checker/server/internal/scan"
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
		debug       = flag.Bool("debug", false, "log at debug level")
	)
	flag.Bool("stdio", true, "communicate over stdio (default, accepted for compatibility)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log, closeLog, err := newLogger(*logPath, *debug)
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
	database, err := db.New(log)
	if err != nil {
		return fmt.Errorf("configure the advisory database: %w", err)
	}

	// The engine and the scanner refer to each other: the engine schedules
	// scans, and a scan that finds the database missing needs to ask for a
	// rescan once the download lands. The callback is set after both exist.
	var eng *engine.Engine
	scanner := scan.New(log, extractor, database, scan.OnDatabaseReady(func() {
		eng.Request(engine.ReasonDatabaseSync)
	}))

	// The server is both the protocol endpoint and the publisher the engine
	// writes through, so it is built before the engine and wired after.
	var srv *lsp.Server
	eng = engine.New(log, scanner, publisherFunc(func(ctx context.Context, path string, findings []model.Finding) error {
		return srv.Publish(ctx, path, findings)
	}))

	defer func() { _ = eng.Close() }()

	srv = lsp.NewServer(log, version, eng)

	// NewServer starts dispatching before it returns, so nothing may be handed
	// to the server after this line. The client it builds rides on the returned
	// context, which is what every handler and the engine's publisher receive.
	stream := jsonrpc2.NewStream(stdio{})
	ctx, conn, _ := protocol.NewServer(ctx, srv, stream)

	// Scheduling starts once the root is known, which happens in Initialize.
	// Starting it here with an empty root would scan the wrong directory.
	go func() {
		<-srv.Ready()
		eng.Start(ctx, srv.Root())
	}()

	<-conn.Done()

	if err := conn.Err(); err != nil {
		return fmt.Errorf("connection closed: %w", err)
	}
	log.Info("connection closed cleanly")
	return nil
}

// publisherFunc adapts a function to engine.Publisher, so the server can be
// constructed after the engine that writes through it.
type publisherFunc func(ctx context.Context, path string, findings []model.Finding) error

func (f publisherFunc) Publish(ctx context.Context, path string, findings []model.Finding) error {
	return f(ctx, path, findings)
}

// newLogger builds a logger that never writes to stdout, plus a function to
// release any file it opened.
//
// stdout carries the JSON-RPC stream; a single stray byte there corrupts the
// protocol. Logs go to stderr, which Zed surfaces in its LSP log, and
// optionally to a file as well for debugging.
func newLogger(path string, debug bool) (*slog.Logger, func(), error) {
	var (
		out       io.Writer = os.Stderr
		closeFile           = func() {}
	)
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
		}
		out = io.MultiWriter(os.Stderr, f)
		closeFile = func() { _ = f.Close() }
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level})), closeFile, nil
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
