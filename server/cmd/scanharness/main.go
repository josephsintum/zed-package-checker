// Command scanharness times a full scan phase by phase, outside the editor.
// Development only.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"log/slog"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/match"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func main() {
	root, _ := filepath.Abs(os.Args[1])
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	extract.SetLogger(log)
	ctx := context.Background()

	t := time.Now()
	ex, err := extract.New()
	if err != nil {
		panic(err)
	}
	pkgs, err := ex.Extract(ctx, root)
	if err != nil {
		panic(err)
	}
	fmt.Printf("extract:  %-8v %d packages\n", time.Since(t).Round(time.Millisecond), len(pkgs))

	var ecos []model.Ecosystem
	counts := map[model.Ecosystem]int{}
	for _, p := range pkgs {
		counts[p.Package.Ecosystem]++
	}
	for e, n := range counts {
		ecos = append(ecos, e)
		fmt.Printf("          %-12s %d\n", e, n)
	}

	t = time.Now()
	d, _ := db.New(log)
	if err := d.Ensure(ctx, ecos); err != nil {
		fmt.Println("ensure:", err)
	}
	fmt.Printf("ensure:   %v\n", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	idx, err := d.Load(ctx, ecos)
	if err != nil {
		panic(err)
	}
	fmt.Printf("load:     %-8v %d advisories\n", time.Since(t).Round(time.Millisecond), idx.Advisories())

	t = time.Now()
	findings, err := match.New(log, idx).Findings(ctx, pkgs)
	if err != nil {
		panic(err)
	}
	fmt.Printf("match:    %-8v %d findings\n", time.Since(t).Round(time.Millisecond), len(findings))

	for i, f := range findings {
		if i >= 20 {
			fmt.Printf("  ... and %d more\n", len(findings)-20)
			break
		}
		fmt.Printf("  %-8s %-45s %s\n", f.Severity(), f.Package, f.Worst().ID)
	}
}
