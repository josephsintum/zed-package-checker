// Package arch holds the architectural boundary test.
//
// It lives in its own package because it is about the module as a whole rather
// than any one part of it.
package arch_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/josephsintum/zed-package-checker/server"

// buildTags must name every tag guarding a file in this module. Without it an
// import behind a tag is invisible to go list, and its boundary would pass
// without ever being checked — which is the case for osv-scanner, whose only
// importer is the differential test.
const buildTags = "differential"

// boundary is a third-party dependency only certain packages may reach.
//
// These are the seams that keep a library swap local. Each is stated in
// docs/PLAN.md; this test is what stops the statement drifting from the code,
// which it had already done for three of the four before this existed.
type boundary struct {
	prefix string
	// owners are package paths relative to the module root.
	owners []string
	why    string
}

var boundaries = []boundary{
	{
		prefix: "go.lsp.dev",
		owners: []string{"internal/lsp"},
		why: "the protocol library is barely maintained; confining it means a " +
			"swap, or a fallback to hand-written structs, touches one package",
	},
	{
		prefix: "github.com/google/osv-scalibr",
		owners: []string{"internal/extract", "internal/match"},
		why: "extraction owns scalibr. internal/match reaches only for the " +
			"semantic package, a pure version-ordering primitive with no " +
			"extraction machinery behind it, which Stage 14's upgrade action " +
			"will also need",
	},
	{
		prefix: "github.com/google/osv-scanner",
		owners: []string{"internal/match"},
		why: "matching is ours now; osv-scanner survives only in the " +
			"build-tagged differential test that checks ours against it",
	},
}

// TestModelHasNoExternalDependencies keeps the domain vocabulary free of
// anything that could drag a third-party type into every other package.
func TestModelHasNoExternalDependencies(t *testing.T) {
	for _, imp := range directImports(t, modulePath+"/internal/model") {
		if isThirdParty(imp) {
			t.Errorf("internal/model imports %s; it must depend on nothing outside the standard library", imp)
		}
	}
}

// TestThirdPartyBoundariesHold checks that each confined dependency is reached
// only from the packages allowed to reach it.
func TestThirdPartyBoundariesHold(t *testing.T) {
	packages := modulePackages(t)

	for _, b := range boundaries {
		t.Run(b.prefix, func(t *testing.T) {
			for _, pkg := range packages {
				rel := strings.TrimPrefix(pkg, modulePath+"/")
				if slices.Contains(b.owners, rel) {
					continue
				}
				for _, imp := range directImports(t, pkg) {
					if strings.HasPrefix(imp, b.prefix) {
						t.Errorf("%s imports %s\n  only %s may: %s",
							rel, imp, strings.Join(b.owners, ", "), b.why)
					}
				}
			}
		})
	}
}

// directImports returns what a package imports itself, including from its
// tests. Transitive dependencies are deliberately excluded: every binary
// reaches go.lsp.dev through internal/lsp, and that is the point of the seam
// rather than a violation of it.
func directImports(t *testing.T, pkg string) []string {
	t.Helper()
	out := run(t, "go", "list", "-tags", buildTags, "-f",
		`{{join .Imports "\n"}}{{"\n"}}{{join .TestImports "\n"}}{{"\n"}}{{join .XTestImports "\n"}}`,
		pkg)

	return nonEmpty(out)
}

// nonEmpty splits command output into trimmed, non-blank lines.
func nonEmpty(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func modulePackages(t *testing.T) []string {
	t.Helper()
	pkgs := nonEmpty(run(t, "go", "list", "-tags", buildTags, "./..."))
	// A wrong working directory narrows this sweep instead of failing it, which
	// is how every cmd package once sat outside the boundary check while the
	// test still passed. Assert the shape of what came back rather than trust
	// that it covered the module.
	var sawCmd, sawInternal bool
	for _, pkg := range pkgs {
		rel := strings.TrimPrefix(pkg, modulePath+"/")
		sawCmd = sawCmd || strings.HasPrefix(rel, "cmd/")
		sawInternal = sawInternal || strings.HasPrefix(rel, "internal/")
	}
	if !sawCmd || !sawInternal {
		t.Fatalf("swept %d packages (cmd=%v internal=%v): this is not the whole module",
			len(pkgs), sawCmd, sawInternal)
	}
	return pkgs
}

// isThirdParty reports whether an import is neither standard library nor ours.
// Standard library paths have no dot in their first segment.
func isThirdParty(imp string) bool {
	if strings.HasPrefix(imp, modulePath) {
		return false
	}
	first, _, _ := strings.Cut(imp, "/")
	return strings.Contains(first, ".")
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	// Tests run in their own package directory, so the module root is two up
	// from internal/arch. Getting this wrong silently narrows the sweep to
	// whatever subtree it lands in rather than failing.
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}
