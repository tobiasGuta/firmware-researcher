package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateSingleFirmware(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "router.bin")
	write(t, path, []byte("router firmware"))
	m, err := Generate(Options{FirmwarePath: path})
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte("router firmware"))
	if m.Firmware.SHA256 != hex.EncodeToString(expected[:]) || m.Firmware.Size != 15 || m.Firmware.Name != "router.bin" {
		t.Fatalf("incorrect firmware identity: %+v", m.Firmware)
	}
	if m.ExtractionStatus != "not_provided" || m.Files == nil || len(m.Files) != 0 {
		t.Fatalf("incorrect empty inventory: %+v", m)
	}
}

func TestGenerateInventoryDeterministicAndConservative(t *testing.T) {
	root := t.TempDir()
	firmware := filepath.Join(root, "firmware.bin")
	extraction := filepath.Join(root, "extracted")
	write(t, firmware, []byte{1, 2, 3, 4})
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[18] = 40 // ARM little endian
	write(t, filepath.Join(extraction, "usr/bin/server"), elf)
	write(t, filepath.Join(extraction, "etc/config.ini"), []byte("device=lab\n"))
	write(t, filepath.Join(extraction, "www/app.js"), []byte("console.log('hi')"))
	write(t, filepath.Join(extraction, "bin/start"), []byte("#!/bin/sh\necho demo\n"))
	m1, err := Generate(Options{FirmwarePath: firmware, ExtractedRoot: extraction})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := Generate(Options{FirmwarePath: firmware, ExtractedRoot: extraction})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		t.Fatal("nondeterministic manifest")
	}
	if m1.ExtractionStatus != "externally_supplied_unverified" || m1.InventoryTotals.Files != 4 {
		t.Fatalf("invalid totals %+v", m1)
	}
	paths := []string{"bin/start", "etc/config.ini", "usr/bin/server", "www/app.js"}
	for i, path := range paths {
		if m1.Files[i].Path != path {
			t.Fatalf("order %+v", m1.Files)
		}
	}
	if m1.Files[0].Kind != "script" || m1.Files[1].Kind != "configuration_candidate" || m1.Files[2].Kind != "elf" || m1.Files[2].Architecture != "arm" || m1.Files[3].Kind != "web_asset" {
		t.Fatalf("bad classification %+v", m1.Files)
	}
	for _, entry := range m1.Files {
		if strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "..") {
			t.Fatalf("untrusted path %+v", entry)
		}
	}
}

func TestRejectSymlinkInInventory(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "firmware.bin")
	write(t, input, []byte("x"))
	extracted := filepath.Join(root, "extracted")
	write(t, filepath.Join(extracted, "ok"), []byte("ok"))
	if err := os.Symlink(input, filepath.Join(extracted, "escape")); err != nil {
		t.Skip(err)
	}
	_, err := Generate(Options{FirmwarePath: input, ExtractedRoot: extracted})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestRejectSymlinkRootAndFirmware(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "firmware.bin")
	write(t, input, []byte("x"))
	linked := filepath.Join(root, "firmware-symlink.bin")
	if err := os.Symlink(input, linked); err != nil {
		t.Skip(err)
	}
	if _, err := Generate(Options{FirmwarePath: linked}); err == nil {
		t.Fatal("accepted symlinked firmware")
	}
	extracted := filepath.Join(root, "extracted")
	if err := os.Mkdir(extracted, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(extracted, alias); err != nil {
		t.Skip(err)
	}
	if _, err := Generate(Options{FirmwarePath: input, ExtractedRoot: alias}); err == nil {
		t.Fatal("accepted symlinked root")
	}
}

func TestRejectOversizeFirmware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFirmwareBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Generate(Options{FirmwarePath: path}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("wanted limit failure %v", err)
	}
}

func TestRejectOversizeInventoryFile(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "image.bin")
	write(t, image, []byte("ok"))
	extraction := filepath.Join(root, "extracted")
	if err := os.Mkdir(extraction, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(extraction, "huge"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Generate(Options{FirmwarePath: image, ExtractedRoot: extraction}); err == nil {
		t.Fatal("accepted oversized file")
	}
}

func TestWriteNewNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := Manifest{SchemaVersion: 1, Files: []File{}}
	if err := WriteNew(path, m); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, m); err == nil {
		t.Fatal("overwrote existing manifest")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing artifact modified")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %o", info.Mode().Perm())
	}
}

func TestClassifierDoesNotGuessELFFromExtension(t *testing.T) {
	if c := classify("fake.so", []byte("abc")); c.Kind != "unknown" {
		t.Fatalf("guessed ELF: %+v", c)
	}
	if c := classify("file", []byte{0x7f, 'E', 'L', 'F', 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0}); c.Architecture != "" {
		t.Fatalf("accepted invalid byte order: %+v", c)
	}
}
