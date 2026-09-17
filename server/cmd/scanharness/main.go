// Command scanharness times a full scan phase by phase, outside the editor.
// Development only.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/match"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanharness: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("no directory given; usage: scanharness <dir>")
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		return fmt.Errorf("resolve %s: %w", os.Args[1], err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	extract.SetLogger(log)
	ctx := context.Background()

	t := time.Now()
	ex, err := extract.New()
	if err != nil {
		return fmt.Errorf("configure extraction: %w", err)
	}
	pkgs, err := ex.Extract(ctx, root)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	fmt.Printf("extract:  %-8v %d packages\n", time.Since(t).Round(time.Millisecond), len(pkgs))

	counts := map[model.Ecosystem]int{}
	for _, p := range pkgs {
		counts[p.Package.Ecosystem]++
	}
	// Printed in the same order the scan will load them, so two runs of a
	// timing harness can be compared line by line.
	ecos := model.EcosystemsOf(pkgs)
	for _, e := range ecos {
		fmt.Printf("          %-12s %d\n", e, counts[e])
	}

	t = time.Now()
	d, err := db.New(log)
	if err != nil {
		return fmt.Errorf("configure the advisory database: %w", err)
	}
	if err := d.Ensure(ctx, ecos); err != nil {
		fmt.Println("ensure:", err)
	}
	fmt.Printf("ensure:   %v\n", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	idx, err := d.Load(ctx, ecos)
	if err != nil {
		return fmt.Errorf("load advisories: %w", err)
	}
	fmt.Printf("load:     %-8v %d advisories\n", time.Since(t).Round(time.Millisecond), idx.Advisories())

	t = time.Now()
	findings, err := match.New(log, idx).Findings(ctx, pkgs)
	if err != nil {
		return fmt.Errorf("match: %w", err)
	}
	fmt.Printf("match:    %-8v %d findings\n", time.Since(t).Round(time.Millisecond), len(findings))

	const shown = 20
	for i, f := range findings {
		if i >= shown {
			fmt.Printf("  ... and %d more\n", len(findings)-shown)
			break
		}
		fmt.Printf("  %-8s %-45s %s\n", f.Severity(), f.Package, f.Worst().ID)
	}
	return nil
}
