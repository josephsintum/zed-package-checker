package db

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// writeAtomic writes what src produces to path, such that a reader sees either
// the previous contents or the complete new ones, never a partial write.
//
// This is the whole reason internal/db owns fetching rather than delegating to
// osv-scanner, whose cache write is a plain os.WriteFile: that truncates the
// file and then streams hundreds of megabytes into it, leaving a window of
// several seconds where another process reads a half-written archive. Since Zed
// runs one server per worktree, concurrent readers are the normal case.
//
// verify runs against the finished temporary file before it is published, so
// bytes that failed to download are discarded rather than installed.
func writeAtomic(path string, src func(w io.Writer) error, verify func(tmpPath string) error) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	// Same directory as the target, so the rename stays within one filesystem
	// and is therefore atomic. A temp dir could be on another mount, where
	// rename degrades to copy-then-delete and loses that guarantee.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err := src(tmp); err != nil {
		tmp.Close()
		return err
	}
	// Flush to disk before publishing: a rename can otherwise be visible after
	// a crash while the contents are not.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}

	if verify != nil {
		if err := verify(tmpName); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	return rename(tmpName, path)
}

// writeFileAtomic is writeAtomic for a small in-memory payload.
func writeFileAtomic(path string, data []byte, _ os.FileMode) error {
	return writeAtomic(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}, nil)
}

// rename publishes the temporary file, retrying on Windows.
//
// POSIX replaces the target atomically even while another process has it open.
// Windows refuses if the target is open without FILE_SHARE_DELETE, which a
// concurrent reader may briefly hold, so the rename is retried rather than
// failing a refresh over a millisecond of overlap.
func rename(from, to string) error {
	err := os.Rename(from, to)
	if err == nil || runtime.GOOS != "windows" {
		if err != nil {
			return fmt.Errorf("publish %s: %w", to, err)
		}
		return nil
	}

	delay := 20 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(delay)
		delay *= 2
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			break
		}
	}
	return fmt.Errorf("publish %s after retries: %w", to, err)
}
