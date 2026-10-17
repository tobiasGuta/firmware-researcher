package reva

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/tobiasGuta/firmware-researcher/internal/ingest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTarget(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	rel := "firmware.img.extracted/1C00000/squashfs-root/usr/sbin/uhttpd"
	binary := filepath.Join(root, "extracted", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	elf := make([]byte, 40)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	elf[18] = 40
	if err := os.WriteFile(binary, elf, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(elf)
	m := ingest.Manifest{SchemaVersion: 1, Firmware: ingest.Firmware{Name: "iotgoat.img", SHA256: strings.Repeat("f", 64), Size: 1024}, ExtractionStatus: "isolated_binwalk_success_unverified_coverage", Extraction: &ingest.Extraction{Engine: "binwalk"}, Files: []ingest.File{{Path: rel, SHA256: hex.EncodeToString(h[:]), Size: int64(len(elf)), Classification: ingest.Classification{Kind: "elf", Architecture: "arm", ELFClass: "32-bit"}}}}
	if err := ingest.WriteNew(filepath.Join(root, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	return root, binary
}
func TestSelectARMComponent(t *testing.T) {
	session, binary := setupTarget(t)
	result, err := Select(session, "uhttpd")
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalPath != binary || result.Architecture != "arm" || result.Size != 40 {
		t.Fatalf("wrong target: %+v", result)
	}
}
func TestSelectRejectsMutatedBinary(t *testing.T) {
	session, binary := setupTarget(t)
	if err := os.WriteFile(binary, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Select(session, "uhttpd"); err == nil {
		t.Fatal("accepted modified bytes")
	}
}
func TestSelectRejectsSymlink(t *testing.T) {
	session, binary := setupTarget(t)
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", binary); err != nil {
		t.Fatal(err)
	}
	if _, err := Select(session, "uhttpd"); err == nil {
		t.Fatal("accepted symlinked ELF")
	}
}
func TestSelectRejectsPathAndUnknownName(t *testing.T) {
	session, _ := setupTarget(t)
	for _, name := range []string{"../uhttpd", "/bin/uhttpd", "absent", ""} {
		if _, err := Select(session, name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
func TestWriteNewNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record.json")
	if err := WriteNew(p, Overview{SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, Overview{SchemaVersion: 1}); err == nil {
		t.Fatal("overwrote evidence")
	}
}
