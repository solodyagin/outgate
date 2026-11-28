//go:build linux

package keyring

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestSecretFIFOIsRejectedBeforeOpen(t *testing.T) {
	name := filepath.Join(t.TempDir(), "secret-fifo")
	require(t, syscall.Mkfifo(name, 0600))
	if secret, err := readSecret(t.Context(), Reference{SecretFile: name}); err != ErrUnavailable {
		clear(secret)
		t.Fatal("FIFO not rejected before blocking open", err)
	}
}
