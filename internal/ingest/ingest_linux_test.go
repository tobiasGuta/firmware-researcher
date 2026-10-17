//go:build linux

package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRejectFIFO(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "image.bin")
	if err := os.WriteFile(image, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(root, "extracted")
	if err := os.Mkdir(extracted, 0700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(extracted, "pipe"), 0600); err != nil {
		t.Skip(err)
	}
	_, err := Generate(Options{FirmwarePath: image, ExtractedRoot: extracted})
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("expected FIFO rejection: %v", err)
	}
}
