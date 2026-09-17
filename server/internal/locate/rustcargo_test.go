package locate

import "testing"

func TestCargoTomlSpans(t *testing.T) {
	src := lines(
		`[package]`,
		`name = "fixture"`,
		`version = "1.0.0"`,
		``,
		`[dependencies]`,
		`time = "0.1.44"`,
		`serde = { version = "1.0", features = ["derive"] }`,
		`fast = { package = "real-crate", version = "2.0" }`,
		`local = { path = "../local" }`,
		``,
		`[dev-dependencies]`,
		`criterion = "0.5"   # benchmarks only`,
		``,
		`[target.'cfg(unix)'.dependencies]`,
		`nix = "0.27"`)

	got := CargoToml([]byte(src), "/p/Cargo.toml")

	tests := []struct {
		crate   string
		wantDec at
		wantVer *at
	}{
		{crate: "time", wantDec: at{line: 5, start: 0, end: 4}, wantVer: &at{line: 5, start: 8, end: 14}},
		// The declaration is the key; the version sits inside the inline table.
		{crate: "serde", wantDec: at{line: 6, start: 0, end: 5}, wantVer: &at{line: 6, start: 21, end: 24}},
		// Renamed: keyed by the crate actually depended on, since that is what
		// an advisory names — but anchored on the key the user can edit.
		{crate: "real-crate", wantDec: at{line: 7, start: 0, end: 4}, wantVer: &at{line: 7, start: 44, end: 47}},
		// A path dependency has no version to point at.
		{crate: "local", wantDec: at{line: 8, start: 0, end: 5}, wantVer: nil},
		{crate: "criterion", wantDec: at{line: 11, start: 0, end: 9}, wantVer: &at{line: 11, start: 13, end: 16}},
		// Target-specific tables are dependency tables too.
		{crate: "nix", wantDec: at{line: 14, start: 0, end: 3}, wantVer: &at{line: 14, start: 7, end: 11}},
	}

	for _, tt := range tests {
		t.Run(tt.crate, func(t *testing.T) {
			anchor, ok := got[tt.crate]
			if !ok {
				t.Fatalf("%q not located; got %d entries", tt.crate, len(got))
			}
			tt.wantDec.check(t, "declaration", anchor.Declaration.Range)
			switch {
			case tt.wantVer == nil && anchor.Version != nil:
				t.Errorf("version span = %+v, want none", anchor.Version.Range)
			case tt.wantVer != nil && anchor.Version == nil:
				t.Error("no version span")
			case tt.wantVer != nil:
				tt.wantVer.check(t, "version", anchor.Version.Range)
			}
		})
	}
}

func TestCargoTomlIgnoresThePackageTable(t *testing.T) {
	// [package] names the project, not something it depends on.
	src := lines(`[package]`, `name = "fixture"`, `version = "1.0.0"`)
	if got := CargoToml([]byte(src), "/p/Cargo.toml"); got != nil {
		t.Errorf("located %v in a manifest with no dependencies", got)
	}
}

func TestCargoTomlPrefersTheProductionDeclaration(t *testing.T) {
	src := lines(
		`[dev-dependencies]`,
		`time = "0.2"`,
		``,
		`[dependencies]`,
		`time = "0.1.44"`)

	anchor := CargoToml([]byte(src), "/p/Cargo.toml")["time"]
	at{line: 4, start: 0, end: 4}.check(t, "declaration", anchor.Declaration.Range)
}
