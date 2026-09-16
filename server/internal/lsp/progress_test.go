package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"go.lsp.dev/protocol"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// progressClient records $/progress traffic. Separate from fakeClient because
// these tests care about ordering, which diagnostics tests do not.
type progressClient struct {
	protocol.UnimplementedClient
	mu       sync.Mutex
	created  []protocol.ProgressToken
	values   []map[string]any
	tokens   []protocol.ProgressToken
	createrr error
}

func (c *progressClient) WorkDoneProgressCreate(_ context.Context, p *protocol.WorkDoneProgressCreateParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.createrr != nil {
		return c.createrr
	}
	c.created = append(c.created, p.Token)
	return nil
}

func (c *progressClient) Progress(_ context.Context, p *protocol.ProgressParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var v map[string]any
	if err := json.Unmarshal(p.Value, &v); err != nil {
		return err
	}
	c.values = append(c.values, v)
	c.tokens = append(c.tokens, p.Token)
	return nil
}

func (c *progressClient) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.values))
	for _, v := range c.values {
		kind, _ := v["kind"].(string)
		out = append(out, kind)
	}
	return out
}

func (c *progressClient) at(i int) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[i]
}

func newProgress(t *testing.T) (*DownloadProgress, context.Context, *progressClient) {
	t.Helper()
	client := &progressClient{}
	p := NewDownloadProgress(slog.New(slog.NewTextHandler(io.Discard, nil)))
	return p, protocol.WithClient(t.Context(), client), client
}

func TestProgressReportsBeginReportEnd(t *testing.T) {
	p, ctx, client := newProgress(t)
	const total = 200 << 20

	p.Start(ctx, model.EcosystemNPM, total)
	p.Advance(ctx, model.EcosystemNPM, 100<<20, total)
	p.Done(ctx, model.EcosystemNPM, nil)

	got := client.kinds()
	want := []string{"begin", "report", "end"}
	if len(got) != len(want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("notification %d = %q, want %q", i, got[i], want[i])
		}
	}

	if len(client.created) != 1 {
		t.Fatalf("created %d tokens, want 1", len(client.created))
	}
	for i, tok := range client.tokens {
		if tok != client.created[0] {
			t.Errorf("notification %d used token %v, want %v", i, tok, client.created[0])
		}
	}

	if pct, ok := client.at(1)["percentage"].(float64); !ok || pct != 50 {
		t.Errorf("report percentage = %v, want 50", client.at(1)["percentage"])
	}
}

func TestProgressWithoutAClientDoesNothing(t *testing.T) {
	// The download runs whether or not anything is watching it.
	p := NewDownloadProgress(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.Start(t.Context(), model.EcosystemNPM, 10)
	p.Advance(t.Context(), model.EcosystemNPM, 5, 10)
	p.Done(t.Context(), model.EcosystemNPM, nil)
}

func TestProgressStopsWhenTheClientRefusesTheToken(t *testing.T) {
	p, ctx, client := newProgress(t)
	client.createrr = errors.New("unsupported")

	p.Start(ctx, model.EcosystemNPM, 10)
	p.Advance(ctx, model.EcosystemNPM, 5, 10)
	p.Done(ctx, model.EcosystemNPM, nil)

	if kinds := client.kinds(); len(kinds) != 0 {
		t.Errorf("sent %v after the token was refused, want nothing", kinds)
	}
}

func TestProgressOmitsPercentageWhenTheSizeIsUnknown(t *testing.T) {
	// Cloud Storage always sends Content-Length, but a mirror or proxy need
	// not. An indeterminate bar beats a fabricated number.
	p, ctx, client := newProgress(t)

	p.Start(ctx, model.EcosystemNPM, -1)
	p.Advance(ctx, model.EcosystemNPM, 5<<20, -1)

	if _, present := client.at(1)["percentage"]; present {
		t.Error("percentage reported for a download of unknown size")
	}
	if msg, _ := client.at(1)["message"].(string); msg != "5.0 MB" {
		t.Errorf("message = %q, want the running count alone", msg)
	}
}

func TestProgressEndsWithTheFailure(t *testing.T) {
	p, ctx, client := newProgress(t)

	p.Start(ctx, model.EcosystemNPM, 10)
	p.Done(ctx, model.EcosystemNPM, errors.New("connection reset"))

	msg, _ := client.at(1)["message"].(string)
	if want := "npm advisories unavailable: connection reset"; msg != want {
		t.Errorf("end message = %q, want %q", msg, want)
	}
}

func TestProgressKeepsEcosystemsApart(t *testing.T) {
	p, ctx, client := newProgress(t)

	p.Start(ctx, model.EcosystemNPM, 10)
	p.Start(ctx, model.EcosystemPyPI, 20)

	if len(client.created) != 2 {
		t.Fatalf("created %d tokens, want one per ecosystem", len(client.created))
	}
	if client.created[0] == client.created[1] {
		t.Error("npm and PyPI shared a progress token")
	}
}

func TestPercentage(t *testing.T) {
	tests := []struct {
		name              string
		downloaded, total int64
		want              *uint32
	}{
		{"unknown total", 50, -1, nil},
		{"zero total", 50, 0, nil},
		{"start", 0, 200, new(uint32(0))},
		{"half", 100, 200, new(uint32(50))},
		{"complete", 200, 200, new(uint32(100))},
		{"over-read is clamped", 300, 200, new(uint32(100))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentage(tt.downloaded, tt.total)
			switch {
			case tt.want == nil && got != nil:
				t.Errorf("percentage = %d, want nil", *got)
			case tt.want != nil && got == nil:
				t.Errorf("percentage = nil, want %d", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("percentage = %d, want %d", *got, *tt.want)
			}
		})
	}
}

func TestDescribeSize(t *testing.T) {
	tests := []struct {
		name              string
		downloaded, total int64
		want              string
	}{
		{"known total", 12 << 20, 205 << 20, "12.0 MB of 205.0 MB"},
		{"unknown total", 12 << 20, -1, "12.0 MB"},
		{"nothing yet", 0, 205 << 20, "0.0 MB of 205.0 MB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeSize(tt.downloaded, tt.total); got != tt.want {
				t.Errorf("describeSize = %q, want %q", got, tt.want)
			}
		})
	}
}
