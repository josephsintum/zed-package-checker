// Package locate narrows a dependency's diagnostic from a whole line to the
// exact span of its name and version.
//
// Everything here is pure: bytes in, ranges out, no filesystem and no I/O. The
// manifest is the only input, so the same bytes always produce the same spans
// and the tests are golden files rather than fixtures on disk.
//
// One file per manifest kind, named language first — npmpackagejson.go,
// gomod.go, pyrequirements.go, rustcargo.go — so everything for a language
// sorts together and no two ecosystems contend for a name. The format alone
// would not be enough: pyproject.toml and Cargo.toml are both TOML, and four
// ecosystems have a lockfile. Files that are not specific to one language,
// such as offset.go, take no prefix.
package locate
