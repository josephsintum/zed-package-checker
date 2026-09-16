// Command extractharness runs dependency extraction over a directory and
// prints what it found.
//
// It exists so extraction can be exercised without the editor in the loop.
// Not shipped: the release build is cmd/package-checker-lsp.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "extractharness: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	exclude := flag.String("exclude", "", "comma-separated extra directory names to skip")
	flag.Parse()

	if flag.NArg() != 1 {
		return fmt.Errorf("usage: extractharness [-exclude a,b] <dir>")
	}
	root, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("resolve %s: %w", flag.Arg(0), err)
	}

	var opts []extract.Option
	if *exclude != "" {
		opts = append(opts, extract.WithExclude(strings.Split(*exclude, ",")...))
	}
	extractor, err := extract.New(opts...)
	if err != nil {
		return err
	}

	start := time.Now()
	pkgs, err := extractor.Extract(context.Background(), root)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	fmt.Printf("%s\n%d packages in %v\n\n", root, len(pkgs), elapsed.Round(time.Microsecond))
	// Ranges are zero-based; reported one-based so they match the editor.
	show := func(s model.Site) string {
		rel, err := filepath.Rel(root, s.Path)
		if err != nil {
			rel = s.Path
		}
		return fmt.Sprintf("%s:%d", rel, s.Range.Start.Line+1)
	}

	for _, p := range pkgs {
		anchor := p.Evidence
		if p.Declared != nil {
			anchor = *p.Declared
		}
		fmt.Printf("  %-40s %s", p.Package, show(anchor))
		if p.Declared != nil {
			fmt.Printf("  (resolved at %s)", show(p.Evidence))
		}
		if p.FromRange {
			fmt.Print("  [from-range]")
		}
		if len(p.DepGroups) > 0 {
			fmt.Printf("  groups=%v", p.DepGroups)
		}
		fmt.Println()
	}
	return nil
}
