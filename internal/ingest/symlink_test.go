package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordLinkMetadataWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "firmware.bin")
	if err := os.WriteFile(image, []byte("fw"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "out")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(dir, "link")); err != nil {
		t.Skip(err)
	}
	result, err := Generate(Options{FirmwarePath: image, ExtractedRoot: dir, RecordSymlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.InventoryTotals.Files != 1 || result.InventoryTotals.Symlinks != 1 || len(result.Links) != 1 || result.Links[0].Target != "/etc/shadow" {
		t.Fatalf("unexpected inventory %+v", result)
	}
}
