// Package extract finds the dependencies a project declares or locks.
//
// It is the only package permitted to import osv-scalibr, and converts scalibr's
// types into model types at its boundary. It reports what is present and makes
// no judgement about whether it is safe; matching advisories is internal/match.
package extract

import (
	"context"
	"fmt"
	"regexp"

	scalibr "github.com/google/osv-scalibr"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Extractor discovers dependencies under a project root.
type Extractor struct {
	plugins []plugin.Plugin
	skip    *regexp.Regexp
	cfg     config
}

// New builds an Extractor.
//
// Extractors are constructed directly rather than resolved through scalibr's
// plugin registry: packagejson only reads dependencies when IncludeDependencies
// is set, and that lives in a plugin-specific config proto which the registry's
// name-based enabling cannot express.
func New(opts ...Option) (*Extractor, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	skip, err := skipRegex(cfg.extraSkip)
	if err != nil {
		return nil, err
	}

	pluginCfg := &cpb.PluginConfig{
		PluginSpecific: []*cpb.PluginSpecificConfig{{
			Config: &cpb.PluginSpecificConfig_JavascriptPackageJson{
				JavascriptPackageJson: &cpb.JavascriptPackageJsonConfig{
					// Without this, packagejson reports only the manifest's own
					// identity and none of its dependencies, so a project with
					// no lockfile yields nothing.
					IncludeDependencies: true,
				},
			},
		}},
	}

	plugins, err := buildPlugins(pluginCfg)
	if err != nil {
		return nil, err
	}

	return &Extractor{plugins: plugins, skip: skip, cfg: cfg}, nil
}

// buildPlugins constructs every extractor, failing if any cannot be built
// rather than silently scanning less than expected.
func buildPlugins(cfg *cpb.PluginConfig) ([]plugin.Plugin, error) {
	constructors := []struct {
		name string
		new  func(*cpb.PluginConfig) (filesystemExtractor, error)
	}{
		{packagejson.Name, adapt(packagejson.New)},
		{packagelockjson.Name, adapt(packagelockjson.New)},
		{gomod.Name, adapt(gomod.New)},
		{requirements.Name, adapt(requirements.New)},
	}

	plugins := make([]plugin.Plugin, 0, len(constructors))
	for _, c := range constructors {
		p, err := c.new(cfg)
		if err != nil {
			return nil, fmt.Errorf("build extractor %s: %w", c.name, err)
		}
		plugins = append(plugins, p)
	}
	return plugins, nil
}

// Extract walks root and returns every dependency found.
//
// A project with no recognised manifests yields an empty slice, not an error:
// the server attaches to nearly every language, so most workspaces it starts in
// legitimately have nothing to extract.
func (e *Extractor) Extract(ctx context.Context, root string) ([]model.ExtractedPackage, error) {
	result := scalibr.New().Scan(ctx, &scalibr.ScanConfig{
		Plugins:   e.plugins,
		ScanRoots: scalibrfs.RealFSScanRoots(root),
		// Without this, paths come back relative to the filesystem root with no
		// leading slash, which produces URIs the editor ignores.
		StoreAbsolutePath: true,
		SkipDirRegex:      e.skip,
		MaxInodes:         e.cfg.maxInodes,
		Capabilities:      &plugin.Capabilities{},
	})

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("extract %s: scan returned no result", root)
	}
	// A partial success means some files could not be read while others were
	// extracted fine. Those results are still worth reporting, so only an
	// outright failure is an error.
	if s := result.Status; s != nil && s.Status == plugin.ScanStatusFailed {
		return nil, fmt.Errorf("extract %s: %s", root, s.FailureReason)
	}

	return convert(result.Inventory.Packages), nil
}
