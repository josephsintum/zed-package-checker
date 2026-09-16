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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
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
	load := flag.Bool("load", false, "also build the in-memory index and report its size")
	scans := flag.Int("scans", 0, "lookups to perform after loading, to show the index is reused")
	verbose := flag.Bool("v", false, "show the database's own logging")
	flag.Parse()

	if flag.NArg() == 0 {
		return errors.New("no ecosystem given; usage: dbcheck [-root DIR] [-runs N] <ecosystem>")
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

	if *load {
		start := time.Now()
		idx, err := d.Load(context.Background(), ecosystems)
		if err != nil {
			return err
		}
		elapsed := time.Since(start)

		var ms runtime.MemStats
		runtime.GC() // settle the heap so HeapAlloc reflects what is retained
		runtime.ReadMemStats(&ms)
		runtime.KeepAlive(idx)

		fmt.Printf("\nindex: %d advisories over %d packages in %v\n",
			idx.Advisories(), idx.Packages(), elapsed.Round(time.Millisecond))
		fmt.Printf("  retained heap after load: %.1f MB\n", float64(ms.HeapAlloc)/(1<<20))

		for i := 0; i < *scans; i++ {
			idx.Lookup(model.PackageKey{Ecosystem: ecosystems[0], Name: "lodash"})
		}
		if *scans > 0 {
			runtime.GC()
			runtime.ReadMemStats(&ms)
			fmt.Printf("  retained heap after %d lookups: %.1f MB\n",
				*scans, float64(ms.HeapAlloc)/(1<<20))
		}
		// Without this the index is unreachable by the time the stats are
		// read, and the numbers above measure a collected heap.
		runtime.KeepAlive(idx)
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
