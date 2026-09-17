// Command load-phases splits the Go loader's cost into inflating zip entries and
// parsing JSON, so "Rust is faster" can be replaced with an attribution.
//
// It decodes into the same partial struct internal/db uses, so the parse figure
// is like for like — except that it stops at Unmarshal, where the real loader
// goes on to build the domain types. The Rust side's parse figure includes that
// extra step, so the comparison understates Rust rather than flattering it.
//
// A separate Go module on purpose: it exists to measure the server, and must
// never become something the server depends on.
//
//	go run . -archive ~/Library/Caches/.../npm/all.zip [-fast]
//
// -fast registers github.com/klauspost/compress as archive/zip's inflater,
// which the standard library explicitly supports and which is already an
// indirect dependency of the server.
package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	kpflate "github.com/klauspost/compress/flate"
)

type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type versionRange struct {
	Events []event `json:"events"`
}

type affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges   []versionRange `json:"ranges"`
	Versions []string       `json:"versions"`
}

type reference struct {
	URL string `json:"url"`
}

// advisory mirrors internal/db's osvAdvisory, including Details — the field it
// decodes and then discards.
type advisory struct {
	ID         string      `json:"id"`
	Withdrawn  string      `json:"withdrawn"`
	Aliases    []string    `json:"aliases"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Severity   []severity  `json:"severity"`
	Affected   []affected  `json:"affected"`
	References []reference `json:"references"`
}

func main() {
	archive := flag.String("archive", "", "path to an all.zip")
	fast := flag.Bool("fast", false, "use klauspost/compress instead of compress/flate")
	flag.Parse()

	if *archive == "" {
		fmt.Fprintln(os.Stderr, "usage: load-phases -archive PATH [-fast]")
		os.Exit(2)
	}
	if err := run(*archive, *fast); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(archive string, fast bool) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()

	if fast {
		r.RegisterDecompressor(zip.Deflate, func(in io.Reader) io.ReadCloser {
			return kpflate.NewReader(in)
		})
	}

	var inflate, parse time.Duration
	entries, decoded := 0, 0
	// One buffer for the whole archive, so the measurement is not dominated by
	// an allocation the real loader does not make either.
	buf := make([]byte, 0, 1<<16)
	start := time.Now()

	for _, entry := range r.File {
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		entries++

		began := time.Now()
		f, err := entry.Open()
		if err != nil {
			continue
		}
		buf = buf[:0]
		buf, err = appendAll(buf, f)
		f.Close()
		inflate += time.Since(began)
		if err != nil {
			continue
		}

		began = time.Now()
		var a advisory
		if json.Unmarshal(buf, &a) == nil {
			decoded++
		}
		parse += time.Since(began)
	}

	inflater := "compress/flate"
	if fast {
		inflater = "klauspost/compress"
	}
	fmt.Printf("inflater %s\n", inflater)
	fmt.Printf("entries  %d  decoded %d\n", entries, decoded)
	fmt.Printf("inflate  %v\nparse    %v\ntotal    %v\n",
		inflate.Round(time.Millisecond),
		parse.Round(time.Millisecond),
		time.Since(start).Round(time.Millisecond))
	return nil
}

func appendAll(dst []byte, r io.Reader) ([]byte, error) {
	chunk := make([]byte, 32*1024)
	for {
		n, err := r.Read(chunk)
		dst = append(dst, chunk[:n]...)
		if err == io.EOF {
			return dst, nil
		}
		if err != nil {
			return dst, err
		}
	}
}
