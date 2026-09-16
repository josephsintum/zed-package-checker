package model

// Ecosystem identifies a package registry.
//
// Values are the exact OSV strings including capitalisation — they appear in
// advisory data and in the database layout, so normalising case breaks
// matching.
type Ecosystem string

// Ecosystems with extraction and matching support. OSV defines many more.
const (
	EcosystemNPM    Ecosystem = "npm"
	EcosystemGo     Ecosystem = "Go"
	EcosystemPyPI   Ecosystem = "PyPI"
	EcosystemCrates Ecosystem = "crates.io"
)

// String returns the OSV name.
func (e Ecosystem) String() string { return string(e) }

// Valid reports whether the checker supports e.
func (e Ecosystem) Valid() bool {
	switch e {
	case EcosystemNPM, EcosystemGo, EcosystemPyPI, EcosystemCrates:
		return true
	default:
		return false
	}
}

// EcosystemFromPURLType maps a Package URL type to an Ecosystem.
//
// Extraction reports purl types ("golang", "pypi"), which differ from OSV's
// names; this is the only place that translation happens. Unsupported types
// return the zero value, which callers treat as "skip" rather than an error.
func EcosystemFromPURLType(purlType string) Ecosystem {
	switch purlType {
	case "npm":
		return EcosystemNPM
	case "golang":
		return EcosystemGo
	case "pypi":
		return EcosystemPyPI
	case "cargo":
		return EcosystemCrates
	default:
		return ""
	}
}
