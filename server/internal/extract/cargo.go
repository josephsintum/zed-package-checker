package extract

import (
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// dropCargoSelf removes the crate a Cargo project declares as its own.
//
// A project is not a dependency of itself, and reporting an advisory against it
// would be wrong. npm gets this for free: packagejson marks its own entry with
// metadata, which isSelf reads. Cargo gives nothing to read — cargolock lists
// every [[package]] in the lockfile including the local one, and cargotoml
// emits the [package] table alongside the dependencies — so the manifest is
// opened to find out which name belongs to the project.
//
// A workspace root carries [workspace] and no [package], so nothing is dropped
// there. Attributing a member's crate correctly needs the dependency graph and
// arrives with it.
func dropCargoSelf(pkgs []model.ExtractedPackage) []model.ExtractedPackage {
	// One read per directory, however many crates it accounts for.
	selfOf := map[string]string{}
	for _, p := range pkgs {
		if p.Package.Ecosystem != model.EcosystemCrates {
			continue
		}
		dir := filepath.Dir(p.Evidence.Path)
		if _, read := selfOf[dir]; !read {
			selfOf[dir] = cargoPackageName(filepath.Join(dir, "Cargo.toml"))
		}
	}
	if len(selfOf) == 0 {
		return pkgs
	}

	out := pkgs[:0]
	for _, p := range pkgs {
		own := selfOf[filepath.Dir(p.Evidence.Path)]
		if p.Package.Ecosystem == model.EcosystemCrates && own != "" && p.Package.Name == own {
			continue
		}
		out = append(out, p)
	}
	return out
}

// cargoPackageName returns the crate a Cargo.toml declares, or "" when the file
// is absent, unreadable, or a workspace root with no [package] of its own.
func cargoPackageName(path string) string {
	var manifest struct {
		Package struct {
			Name string `toml:"name"`
		} `toml:"package"`
	}
	if _, err := toml.DecodeFile(path, &manifest); err != nil {
		return ""
	}
	return manifest.Package.Name
}
