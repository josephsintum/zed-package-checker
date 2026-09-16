package extract

import (
	"fmt"
	"regexp"
	"strings"
)

// builtinSkipDirs are never descended into.
//
// These are not a user preference but a correctness property: a manifest inside
// node_modules describes a dependency's own package, and reporting against it
// is simply wrong. User patterns add to this list rather than replacing it, so
// excluding one fixture directory cannot accidentally disable the rest.
var builtinSkipDirs = []string{
	"node_modules",
	".git",
	".venv",
	"venv",
	"vendor",
	"target",
	"dist",
}

// Option configures an Extractor.
type Option func(*config)

type config struct {
	extraSkip  []string
	maxInodes  int
	ecosystems []string
}

// WithExclude adds directory names to skip, on top of the built-in list.
//
// Entries are matched against a single path segment, so "fixtures" skips any
// directory with that name at any depth.
func WithExclude(dirs ...string) Option {
	return func(c *config) { c.extraSkip = append(c.extraSkip, dirs...) }
}

// WithMaxInodes caps how many filesystem entries the walk visits, bounding the
// cost of pointing the scanner at an unexpectedly enormous tree. Zero means no
// limit.
func WithMaxInodes(n int) Option {
	return func(c *config) { c.maxInodes = n }
}

// skipRegex builds the pattern passed to scalibr as SkipDirRegex.
//
// SkipDirRegex is used rather than DirsToSkip because the latter expects paths
// relative to the scan roots; bare directory names silently fail to match.
// Names are quoted, so a user pattern containing regex metacharacters is
// treated literally rather than compiling into something surprising.
func skipRegex(extra []string) (*regexp.Regexp, error) {
	names := make([]string, 0, len(builtinSkipDirs)+len(extra))
	for _, n := range append(append([]string{}, builtinSkipDirs...), extra...) {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, regexp.QuoteMeta(n))
		}
	}
	// Anchored to a full path segment so "dist" does not also match "district".
	pattern := `(^|/)(` + strings.Join(names, "|") + `)$`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("build skip pattern %q: %w", pattern, err)
	}
	return re, nil
}
