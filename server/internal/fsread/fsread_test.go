package fsread

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestBoundedReadsAFileUnderTheCap(t *testing.T) {
	path := write(t, "go.mod", []byte("module example.com/x\n"))
	got, err := bounded(path, 64)
	if err != nil {
		t.Fatalf("bounded: %v", err)
	}
	if string(got) != "module example.com/x\n" {
		t.Errorf("got %q", got)
	}
}

func TestBoundedRejectsAFileOverTheCap(t *testing.T) {
	path := write(t, "go.mod", []byte("123456789"))

	if _, err := bounded(path, 8); !errors.Is(err, ErrTooLarge) {
		t.Errorf("nine bytes under an eight-byte cap: got %v, want ErrTooLarge", err)
	}
	// One byte under is the boundary that must still succeed.
	if _, err := bounded(path, 9); err != nil {
		t.Errorf("nine bytes under a nine-byte cap: %v", err)
	}
}

func TestTheShippedCapRejectsAnOversizedFile(t *testing.T) {
	// Truncate writes nothing and costs one syscall, so the real constant is
	// exercised without a sixteen-megabyte fixture.
	path := write(t, "package-lock.json", nil)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := f.Truncate(MaxManifestBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := Manifest(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

func TestAFileThatGrowsPastTheCapAfterTheStatIsRejected(t *testing.T) {
	// What the second check exists for: the stat is a hint, not a guarantee.
	path := write(t, "requirements.txt", []byte("123456789"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.WriteFile(path, []byte("01234567890123456789"), 0o600); err != nil {
		t.Fatalf("grow: %v", err)
	}
	if _, err := bounded(path, info.Size()); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

func TestAMissingFileIsAnError(t *testing.T) {
	if _, err := Manifest(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file must not read as empty")
	}
}

func TestManifestOrNilSwallowsTheError(t *testing.T) {
	if got := ManifestOrNil(nil, filepath.Join(t.TempDir(), "absent")); got != nil {
		t.Errorf("got %q, want nil", got)
	}
}
