//go:build extract

// Stage 0 probe #2: can we do EXTRACTION ONLY via osv-scalibr, skipping
// osv-scanner's vulnerability matching entirely? Answers:
//   - do we still get line numbers?
//   - does StoreAbsolutePath fix the root-relative path problem?
//   - how fast is extraction alone?
//   - how much smaller is the binary without the matcher/container deps?
// Throwaway. Build: go build -tags extract -o dist/extract ./
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"time"

	scalibr "github.com/google/osv-scalibr"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
)

func main() {
	root := os.Args[1]

	cfg := &cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{{
			Config: &cpb.PluginSpecificConfig_JavascriptPackageJson{
				JavascriptPackageJson: &cpb.JavascriptPackageJsonConfig{
					IncludeDependencies: true,
				},
			},
		}},
	}

	var plugins []plugin.Plugin
	add := func(name string, p any, err error) {
		if err != nil {
			fmt.Printf("  !! %s: %v\n", name, err)
			return
		}
		plugins = append(plugins, p.(plugin.Plugin))
	}
	pj, err := packagejson.New(cfg)
	add("packagejson", pj, err)
	pl, err := packagelockjson.New(cfg)
	add("packagelockjson", pl, err)
	gm, err := gomod.New(cfg)
	add("gomod", gm, err)
	rq, err := requirements.New(cfg)
	add("requirements", rq, err)

	t0 := time.Now()
	res := scalibr.New().Scan(context.Background(), &scalibr.ScanConfig{
		Plugins:           plugins,
		ScanRoots:         scalibrfs.RealFSScanRoots(root),
		StoreAbsolutePath: true,
		Capabilities:      &plugin.Capabilities{},
		// DirsToSkip wants paths relative to the scan roots, not bare names.
		// Name-based skipping is SkipDirRegex/SkipDirGlob.
		SkipDirRegex:      regexp.MustCompile(`(^|/)(node_modules|\.venv|vendor|\.git)$`),
	})
	el := time.Since(t0)

	fmt.Printf("\n=== EXTRACT-ONLY: %v status=%v\n", el.Round(time.Microsecond), res.Status)
	for _, p := range res.Inventory.Packages {
		line, path := -1, ""
		if d := p.Location.Descriptor; d != nil && d.File != nil {
			line, path = d.File.LineNumber, d.File.Path
		}
		fmt.Printf("  %-28s %-12s purl=%-10s plugins=%v\n      path=%q line=%d\n",
			p.Name, p.Version, p.PURLType, p.Plugins, path, line)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("  total-alloc=%d MB sys=%d MB\n", ms.TotalAlloc/1048576, ms.Sys/1048576)
}
