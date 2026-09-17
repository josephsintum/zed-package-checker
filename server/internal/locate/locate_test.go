package locate

import (
	"strings"
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// lines joins with \n and a trailing newline, so a test's literal layout is
// exactly the bytes under test.
func lines(l ...string) string { return strings.Join(l, "\n") + "\n" }

// at is the expected span of one token on one line, in zero-based columns.
type at struct {
	line       int
	start, end int
}

func (a at) check(t *testing.T, what string, got model.Range) {
	t.Helper()
	want := model.Range{
		Start: model.Position{Line: a.line, Column: a.start},
		End:   model.Position{Line: a.line, Column: a.end},
	}
	if got != want {
		t.Errorf("%s = %+v, want %+v", what, got, want)
	}
}
