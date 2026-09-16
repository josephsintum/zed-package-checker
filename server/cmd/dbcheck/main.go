// Command dbcheck exercises the advisory database against the real OSV bucket.
//
// The db tests run against a fake server so they stay fast and hermetic, which
// means they prove the logic but not that the live service still behaves as
// expected — headers, conditional requests, archive layout. This closes that
// gap, and is how the Stage 4 gates are checked by hand.
//
// Not shipped: the release build is cmd/package-checker-lsp.
//
//	dbcheck [-root DIR] [-runs N] npm Go PyPI
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dbcheck: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", "", "cache directory (default: the real user cache)")
	runs := flag.Int("runs", 2, "how many times to call Ensure, to show cache reuse")
	verbose := flag.Bool("v", false, "show the database's own logging")
	flag.Parse()

	if flag.NArg() == 0 {
		return fmt.Errorf("usage: dbcheck [-root DIR] [-runs N] <ecosystem>...")
	}

	ecosystems := make([]model.Ecosystem, 0, flag.NArg())
	for _, name := range flag.Args() {
		e := model.Ecosystem(name)
		if !e.Valid() {
			return fmt.Errorf("unsupported ecosystem %q", name)
		}
		ecosystems = append(ecosystems, e)
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var opts []db.Option
	if *root != "" {
		opts = append(opts, db.WithRoot(*root))
	}
	d, err := db.New(log, opts...)
	if err != nil {
		return err
	}

	fmt.Printf("cache: %s\n", d.Root())
	for i := 1; i <= *runs; i++ {
		start := time.Now()
		if err := d.Ensure(context.Background(), ecosystems); err != nil {
			return err
		}
		fmt.Printf("  run %d  %8v  ready=%v\n",
			i, time.Since(start).Round(time.Millisecond), d.Ready(ecosystems))
	}

	fmt.Println()
	for _, e := range ecosystems {
		path := d.ArchivePath(e)
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("  %-12s missing\n", e)
			continue
		}
		fmt.Printf("  %-12s %6.1f MB  %s\n", e, float64(info.Size())/(1<<20), path)
	}
	return nil
}
