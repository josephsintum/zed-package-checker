//go:build !extract

// Stage 0 feasibility probe. Throwaway: answers the six questions in the plan
// that a source read could not settle. Not kept.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

func main() {
	dir := flag.String("dir", "", "directory to scan")
	dbPath := flag.String("db", "", "local OSV db path")
	download := flag.Bool("download", false, "allow DB download")
	extra := flag.Bool("extra", false, "enable packagejson+pyprojecttoml extractors")
	twice := flag.Bool("twice", false, "scan twice to test load() caching")
	flag.Parse()

	build := func() osvscanner.ScannerActions {
		a := osvscanner.ScannerActions{
			DirectoryPaths:    []string{*dir},
			Recursive:         true,
			CompareOffline:    true,
			DownloadDatabases: *download,
			LocalDBPath:       *dbPath,
		}
		a.ExperimentalScannerActions.TransitiveScanning.Disabled = true
		a.PluginNetworkDisabled = !*download
		a.ExperimentalScannerActions.ExcludePatterns = []string{"**/node_modules/**"}
		if *extra {
			a.ExperimentalScannerActions.PluginsEnabled = []string{
				"javascript/packagejson", "python/pyprojecttoml",
			}
		}
		return a
	}

	run := func(label string) {
		t0 := time.Now()
		res, err := osvscanner.DoScan(build())
		el := time.Since(t0)
		ok := err == nil || errors.Is(err, osvscanner.ErrVulnerabilitiesFound)
		fmt.Printf("\n===== %s: %v  err=%v (treated-ok=%v)\n", label, el.Round(time.Millisecond), err, ok)
		if !ok && !errors.Is(err, osvscanner.ErrNoPackagesFound) {
			return
		}
		for _, src := range res.Results {
			fmt.Printf("  SOURCE path=%q type=%q\n", src.Source.Path, src.Source.Type)
			for _, pv := range src.Packages {
				p := pv.Package
				inv := p.Inventory
				fmt.Printf("    PKG %s@%s ecosystem=%q depgroups=%v\n", p.Name, p.Version, p.Ecosystem, pv.DepGroups)
				if inv == nil {
					fmt.Printf("      Inventory: NIL  <-- Q3 FAILS\n")
				} else {
					fmt.Printf("      Inventory: non-nil plugins=%v parentIDs=%d\n", inv.Plugins, len(inv.ParentIDs))
					d := inv.Location.Descriptor
					if d == nil {
						fmt.Printf("      Descriptor: NIL\n")
					} else if d.File == nil {
						fmt.Printf("      Descriptor.File: NIL\n")
					} else {
						fmt.Printf("      LINE: path=%q line=%d  <-- Q3\n", d.File.Path, d.File.LineNumber)
					}
				}
				for _, g := range pv.Groups {
					fmt.Printf("      GROUP ids=%v maxSeverity=%q aliases=%v analysis=%v\n",
						g.IDs, g.MaxSeverity, g.Aliases, g.ExperimentalAnalysis)
				}
			}
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		fmt.Printf("  peak-heap-alloc=%d MB  sys=%d MB\n", ms.TotalAlloc/1048576, ms.Sys/1048576)
	}

	run("scan#1")
	if *twice {
		run("scan#2 (same process)")
	}
	os.Exit(0)
}
