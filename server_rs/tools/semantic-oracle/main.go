// Command semantic-oracle emits how osv-scalibr's comparator orders real
// version strings, so the Rust port can be checked against it rather than
// against someone's reading of the Go source.
//
// It reads the advisory archives already on disk, collects every distinct
// version string an ecosystem actually publishes, and prints a tab-separated
// "a b ordering" corpus. Deliberately a separate Go module: it must never
// become something the Rust server depends on.
package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type advisory struct {
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func main() {
	root := flag.String("root", "", "advisory cache root (the directory holding osv-scalibr/)")
	out := flag.String("out", "", "output file")
	maxPairs := flag.Int("max-pairs", 250000, "comparisons to emit per ecosystem")
	flag.Parse()

	if err := run(*root, *out, *maxPairs, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(root, out string, maxPairs int, ecosystems []string) error {
	if root == "" || out == "" || len(ecosystems) == 0 {
		return fmt.Errorf("usage: semantic-oracle -root DIR -out FILE ECOSYSTEM...")
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	for _, eco := range ecosystems {
		versions, err := collect(filepath.Join(root, "osv-scalibr", eco, "all.zip"), eco)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: %d distinct version strings\n", eco, len(versions))

		emitted := 0
		for i, a := range versions {
			// Two partners per version: the next one in sorted order, which
			// exercises near-ties, and a strided one, which exercises versions
			// that share no prefix.
			for _, j := range []int{(i + 1) % len(versions), (i*7 + 3) % len(versions)} {
				b := versions[j]
				v, err := semantic.Parse(a, eco)
				if err != nil {
					continue
				}
				cmp, err := v.CompareStr(b)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", eco, a, b, cmp)
				emitted++
				if emitted >= maxPairs {
					break
				}
			}
			if emitted >= maxPairs {
				break
			}
		}
		fmt.Fprintf(os.Stderr, "%s: %d comparisons\n", eco, emitted)
	}
	return nil
}

func collect(archive, eco string) ([]string, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	seen := map[string]bool{}
	for _, entry := range r.File {
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			continue
		}
		var a advisory
		err = json.NewDecoder(rc).Decode(&a)
		rc.Close()
		if err != nil {
			continue
		}
		for _, aff := range a.Affected {
			if aff.Package.Ecosystem != eco {
				continue
			}
			for _, v := range aff.Versions {
				if v != "" {
					seen[v] = true
				}
			}
			for _, rng := range aff.Ranges {
				for _, ev := range rng.Events {
					for kind, v := range ev {
						// "0" is a sentinel for "since the beginning", never a
						// version, and the matcher never compares it.
						if v != "" && v != "0" && kind != "limit" {
							seen[v] = true
						}
					}
				}
			}
		}
	}

	versions := make([]string, 0, len(seen))
	for v := range seen {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions, nil
}
