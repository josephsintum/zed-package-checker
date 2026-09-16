package lsp

import (
	"context"
	"io"

	"go.lsp.dev/jsonrpc2"
	"go.lsp.dev/protocol"
)

// Conn is a running JSON-RPC connection, reduced to what a caller waits on.
//
// Declared here so starting the server needs no go.lsp.dev types at the call
// site, which is what keeps the protocol library swappable inside this package.
type Conn interface {
	// Done closes when the connection has finished, for any reason.
	Done() <-chan struct{}

	// Err reports why it finished, or nil for a clean close.
	Err() error
}

// Serve wires srv to a JSON-RPC connection over rwc and begins dispatching.
//
// The returned context carries the client handle, and every handler and
// background task must descend from it — that is how anything pushing to the
// editor, from diagnostics to download progress, finds the client.
//
// Dispatch starts before this returns, so a server must be fully configured
// beforehand: there is no safe moment afterwards to hand it anything.
func Serve(ctx context.Context, srv *Server, rwc io.ReadWriteCloser) (context.Context, Conn) {
	stream := jsonrpc2.NewStream(rwc)
	ctx, conn, _ := protocol.NewServer(ctx, srv, stream)
	return ctx, conn
}
