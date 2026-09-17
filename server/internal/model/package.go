package model

import "fmt"

// PackageKey identifies a package independently of version.
//
// Comparable, so it works as a map key and as the advisory index lookup key.
// Name is the registry's own spelling: "@babel/core" for npm, the full module
// path for Go.
type PackageKey struct {
	Ecosystem Ecosystem
	Name      string
}

// String renders "ecosystem:name". Not a Package URL.
func (k PackageKey) String() string {
	return fmt.Sprintf("%s:%s", k.Ecosystem, k.Name)
}

// IsGoToolchain reports whether this is the Go toolchain itself rather than a
// dependency of the project.
//
// The gomod extractor reports the toolchain as "stdlib", anchored on the `go`
// directive. It is kept as a finding — OSV carries real stdlib advisories — but
// it is not a dependency and should not be described as one.
func (k PackageKey) IsGoToolchain() bool {
	return k.Ecosystem == EcosystemGo && k.Name == "stdlib"
}

// Package is a specific version of a package.
//
// Version is the registry's literal string. Comparison and range containment
// are ecosystem-specific and belong to the matcher, so nothing is lost to
// normalisation before it gets there.
type Package struct {
	PackageKey
	Version string
}

// String renders "ecosystem:name@version".
func (p Package) String() string {
	return fmt.Sprintf("%s@%s", p.PackageKey, p.Version)
}
