package extract

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// extractorPackage aliases scalibr's type so tests can build inputs to convert
// directly, for cases that are awkward to express as a fixture on disk.
type extractorPackage = extractor.Package

// lockedPkg builds a package as a lockfile extractor would report it.
func lockedPkg(name, version, path string, line int) *extractorPackage {
	return &extractorPackage{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeNPM,
		Location: extractor.LocationFromPathAndLine(path, line),
	}
}

// found describes one expected package, in the terms a reader cares about.
type found struct {
	pkg       string // "ecosystem:name@version"
	file      string // basename of the evidence file
	line      int    // one-based, as an editor shows it
	fromRange bool
}

// extractFixture runs extraction over a committed fixture directory.
func extractFixture(t *testing.T, name string, opts ...Option) []model.ExtractedPackage {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("resolve fixture %s: %v", name, err)
	}
	e, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pkgs, err := e.Extract(context.Background(), root)
	if err != nil {
		t.Fatalf("Extract(%s): %v", name, err)
	}
	return pkgs
}

func assertFound(t *testing.T, got []model.ExtractedPackage, want []found) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d packages, want %d", len(got), len(want))
		for _, g := range got {
			t.Logf("  got: %s at %s:%d fromRange=%v",
				g.Package, filepath.Base(g.Evidence.Path), g.Evidence.Range.Start.Line+1, g.FromRange)
		}
		return
	}
	for i, w := range want {
		g := got[i]
		if g.Package.String() != w.pkg {
			t.Errorf("[%d] package = %q, want %q", i, g.Package, w.pkg)
		}
		if base := filepath.Base(g.Evidence.Path); base != w.file {
			t.Errorf("[%d] file = %q, want %q", i, base, w.file)
		}
		// Ranges are zero-based; fixtures are written in editor terms.
		if line := g.Evidence.Range.Start.Line + 1; line != w.line {
			t.Errorf("[%d] line = %d, want %d", i, line, w.line)
		}
		if g.FromRange != w.fromRange {
			t.Errorf("[%d] fromRange = %v, want %v", i, g.FromRange, w.fromRange)
		}
		if !filepath.IsAbs(g.Evidence.Path) {
			t.Errorf("[%d] path %q is not absolute", i, g.Evidence.Path)
		}
	}
}

func TestExtractNpmWithLockfile(t *testing.T) {
	// lodash is declared in package.json and resolved in package-lock.json, so
	// it is found twice and must collapse to one entry anchored on the lockfile,
	// which records the version actually installed.
	assertFound(t, extractFixture(t, "npm-direct"), []found{
		{pkg: "npm:lodash@4.17.15", file: "package-lock.json", line: 14},
	})
}

func TestExtractNpmWithoutLockfile(t *testing.T) {
	// No lockfile, so the manifest is the only source and "^4.17.15" resolves to
	// its lowest satisfying version.
	assertFound(t, extractFixture(t, "npm-nolock"), []found{
		{pkg: "npm:lodash@4.17.15", file: "package.json", line: 5, fromRange: true},
	})
}

func TestExtractGoMod(t *testing.T) {
	// The toolchain is reported as "stdlib", which is a real OSV package with
	// its own advisories, so it is kept rather than filtered.
	assertFound(t, extractFixture(t, "go-mod"), []found{
		{pkg: "Go:github.com/gin-gonic/gin@1.6.0", file: "go.mod", line: 6},
		{pkg: "Go:gopkg.in/yaml.v2@2.2.2", file: "go.mod", line: 7},
		{pkg: "Go:stdlib@1.21", file: "go.mod", line: 3},
	})
}

func TestExtractRequirementsDistinguishesPinsFromRanges(t *testing.T) {
	// "==" is an exact pin and must not be reported as a range; ">=" is.
	assertFound(t, extractFixture(t, "py-requirements"), []found{
		{pkg: "PyPI:requests@2.19.1", file: "requirements.txt", line: 2},
		{pkg: "PyPI:urllib3@1.24", file: "requirements.txt", line: 4, fromRange: true},
	})
}

func TestExtractProjectIsNotItsOwnDependency(t *testing.T) {
	// packagejson emits the manifest's own name@version alongside dependencies.
	for _, fixture := range []string{"npm-direct", "npm-nolock"} {
		t.Run(fixture, func(t *testing.T) {
			for _, p := range extractFixture(t, fixture) {
				if p.Package.Name == fixture+"-fixture" {
					t.Errorf("fixture reported itself as a dependency: %s", p.Package)
				}
			}
		})
	}
}

func TestExtractEmptyDirectory(t *testing.T) {
	// The server starts for nearly every project, so most workspaces have
	// nothing to extract. That is not an error.
	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pkgs, err := e.Extract(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("got %d packages from an empty directory, want 0", len(pkgs))
	}
}

func TestExtractRespectsExcludeOption(t *testing.T) {
	// The whole fixtures tree contains several projects; excluding one by name
	// must remove exactly its packages.
	all := extractFixture(t, ".")
	withoutGo := extractFixture(t, ".", WithExclude("go-mod"))

	if len(withoutGo) >= len(all) {
		t.Fatalf("exclude had no effect: %d vs %d packages", len(withoutGo), len(all))
	}
	for _, p := range withoutGo {
		if p.Package.Ecosystem == model.EcosystemGo {
			t.Errorf("go-mod was excluded but %s was still reported", p.Package)
		}
	}
}

func TestExtractCancelledContext(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures"))
	if _, err := e.Extract(ctx, root); err == nil {
		t.Error("expected an error from a cancelled context")
	}
}

func TestSkipRegex(t *testing.T) {
	re, err := skipRegex([]string{"fixtures", "my.dir"})
	if err != nil {
		t.Fatalf("skipRegex: %v", err)
	}
	tests := []struct {
		path string
		skip bool
	}{
		{"node_modules", true},
		{"a/b/node_modules", true},
		{"a/.git", true},
		{"fixtures", true},         // user-supplied
		{"a/b/fixtures", true},     // at any depth
		{"my.dir", true},           // metacharacter treated literally
		{"myXdir", false},          // so "." must not match any character
		{"district", false},        // anchored to a whole segment
		{"my_node_modules", false}, // likewise
		{"src", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := re.MatchString(tt.path); got != tt.skip {
				t.Errorf("MatchString(%q) = %v, want %v", tt.path, got, tt.skip)
			}
		})
	}
}

func TestSetLoggerRoutesScalibrOutput(t *testing.T) {
	// scalibr logs routine progress at Info, which is per-scan noise; the
	// bridge lowers it so it does not flood the editor's LSP log.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	SetLogger(logger)
	t.Cleanup(func() { SetLogger(slog.New(slog.DiscardHandler)) })

	extractFixture(t, "npm-direct")

	if buf.Len() != 0 {
		t.Errorf("scalibr progress reached an Info logger:\n%s", buf.String())
	}
}

func TestExtractLockfileSupersedesRange(t *testing.T) {
	// "^4.17.0" resolves to 4.17.0, but the lockfile pins 4.17.21. Reporting
	// both would mean matching advisories against a version nobody has
	// installed, so the manifest's inferred version is discarded.
	got := extractFixture(t, "npm-range-vs-lock")
	assertFound(t, got, []found{
		{pkg: "npm:lodash@4.17.21", file: "package-lock.json", line: 11},
	})

	// The manifest line survives as the place to report, since a lockfile is
	// generated and a manifest is what the user edits.
	if len(got) == 1 {
		if got[0].Declared == nil {
			t.Fatal("Declared is nil; the manifest declaration was lost")
		}
		if base := filepath.Base(got[0].Declared.Path); base != "package.json" {
			t.Errorf("Declared file = %q, want package.json", base)
		}
		if line := got[0].Declared.Range.Start.Line + 1; line != 5 {
			t.Errorf("Declared line = %d, want 5", line)
		}
	}
}

func TestExtractKeepsMultipleLockedVersions(t *testing.T) {
	// npm legitimately installs several copies of one package at different
	// versions, and reconciling by name must not collapse them.
	pkgs := convert([]*extractorPackage{
		lockedPkg("lodash", "4.17.21", "/proj/package-lock.json", 10),
		lockedPkg("lodash", "3.10.1", "/proj/package-lock.json", 20),
	})
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 distinct versions: %v", len(pkgs), pkgs)
	}
}

// writeProject lays down one manifest-and-lockfile project under dir.
func writeProject(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestReconciliationIsScopedToOneProject(t *testing.T) {
	// Two projects in one tree, both depending on lodash: one pins it in a
	// lockfile, the other has no lockfile at all. Reconciling them together
	// used to drop the lockfile-free project entirely — a silent false
	// negative — and anchor the locked version on the wrong manifest.
	root := t.TempDir()

	writeProject(t, filepath.Join(root, "locked"), map[string]string{
		"package.json": `{"name":"locked","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}`,
		"package-lock.json": `{"name":"locked","version":"1.0.0","lockfileVersion":3,"packages":{
			"":{"name":"locked","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}},
			"node_modules/lodash":{"version":"4.17.21"}}}`,
	})
	writeProject(t, filepath.Join(root, "unlocked"), map[string]string{
		"package.json": `{"name":"unlocked","version":"1.0.0","dependencies":{"lodash":"^3.0.0"}}`,
	})

	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := e.Extract(context.Background(), root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	byProject := map[string]model.ExtractedPackage{}
	for _, p := range got {
		byProject[filepath.Base(filepath.Dir(p.Evidence.Path))] = p
	}

	locked, ok := byProject["locked"]
	if !ok {
		t.Fatalf("the locked project produced no package; got %d overall", len(got))
	}
	if locked.Package.Version != "4.17.21" {
		t.Errorf("locked project version = %q, want the lockfile's 4.17.21", locked.Package.Version)
	}

	unlocked, ok := byProject["unlocked"]
	if !ok {
		t.Fatal("the lockfile-free project produced no package: another project's lockfile suppressed it")
	}
	if !unlocked.FromRange {
		t.Error("the lockfile-free project's version should be marked as inferred from a range")
	}
	if unlocked.Package.Version == "4.17.21" {
		t.Error("the lockfile-free project took its version from another project's lockfile")
	}

	for _, p := range got {
		declared := p.Evidence.Path
		if p.Declared != nil {
			declared = p.Declared.Path
		}
		if filepath.Dir(declared) != filepath.Dir(p.Evidence.Path) {
			t.Errorf("%s is declared in %s but evidenced in %s: reconciliation crossed projects",
				p.Package, filepath.Dir(declared), filepath.Dir(p.Evidence.Path))
		}
	}
}

func TestAWorkspaceLockfileSupersedesItsMembers(t *testing.T) {
	// A workspace keeps one lockfile at the root and a manifest per member, so
	// the pin that supersedes a member's range sits several directories up.
	// Scoping reconciliation to the exact directory alone would miss it and
	// report the range's lowest satisfying version — a version nobody has
	// installed — alongside the real one.
	root := t.TempDir()

	writeProject(t, root, map[string]string{
		"package.json": `{"name":"ws","version":"1.0.0","workspaces":["packages/*"]}`,
		"package-lock.json": `{"name":"ws","version":"1.0.0","lockfileVersion":3,"packages":{
			"":{"name":"ws","version":"1.0.0"},
			"node_modules/lodash":{"version":"4.17.21"}}}`,
	})
	writeProject(t, filepath.Join(root, "packages", "app"), map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}`,
	})

	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := e.Extract(context.Background(), root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	var versions []string
	for _, p := range got {
		if p.Package.Name == "lodash" {
			versions = append(versions, p.Package.Version)
		}
	}
	if len(versions) != 1 {
		t.Fatalf("lodash reported %d times (%v), want once: the root lockfile governs the member", len(versions), versions)
	}
	if versions[0] != "4.17.21" {
		t.Errorf("lodash version = %q, want the root lockfile's 4.17.21", versions[0])
	}
}
