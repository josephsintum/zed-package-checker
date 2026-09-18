package lsp

import (
	"bytes"

	"go.lsp.dev/protocol"

	"github.com/josephsintum/zed-package-checker/server/internal/fsread"
	"github.com/josephsintum/zed-package-checker/server/internal/locate"
)

// toUTF16Columns rewrites diagnostic columns from UTF-8 bytes into UTF-16 code
// units, in place.
//
// Only reached for a client that declined UTF-8, so the manifest read costs
// nothing in the common case. A file that cannot be read leaves the byte
// columns alone: on an all-ASCII line — which is nearly every dependency line —
// the two encodings agree anyway, so the diagnostic is usually still right and
// is never absent.
//
// RelatedInformation is deliberately untouched. It points into a lockfile, at a
// whole line starting at column zero, which is the same number in both
// encodings.
func toUTF16Columns(path string, diagnostics []protocol.Diagnostic) {
	src, err := fsread.Manifest(path)
	if err != nil {
		return
	}
	lines := bytes.Split(src, []byte("\n"))

	remap := func(p *protocol.Position) {
		if int(p.Line) >= len(lines) {
			return
		}
		p.Character = uint32(locate.Column(lines[p.Line], int(p.Character), locate.UTF16))
	}
	for i := range diagnostics {
		remap(&diagnostics[i].Range.Start)
		remap(&diagnostics[i].Range.End)
	}
}
