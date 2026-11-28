package tlsfiles

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRejectFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t.Context(), path, maxBundle); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
