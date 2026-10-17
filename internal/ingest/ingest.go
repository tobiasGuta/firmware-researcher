// Package ingest builds a read-only inventory of a firmware image and an optional
// externally extracted filesystem. It does not execute firmware or extract data.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	MaxFirmwareBytes    = int64(512 << 20)
	MaxFileBytes        = int64(512 << 20)
	MaxInventoryBytes   = int64(2 << 30)
	MaxInventoryFiles   = 20000
	MaxDirectoryEntries = 50000
)

// Manifest v1 is a deterministic inventory of bytes observed, not an attestation
// that extraction was comprehensive or that source firmware is safe.
type Manifest struct {
	SchemaVersion    int      `json:"schema_version"`
	Firmware         Firmware `json:"firmware"`
	ExtractionStatus string   `json:"extraction_status"`
	Files            []File   `json:"files"`
	InventoryTotals  Totals   `json:"inventory_totals"`
}

type Firmware struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size_bytes"`
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size_bytes"`
	Classification
}

type Totals struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

type Options struct {
	FirmwarePath  string
	ExtractedRoot string
}

func Generate(opts Options) (Manifest, error) {
	if opts.FirmwarePath == "" {
		return Manifest{}, errors.New("firmware path is required")
	}
	digest, n, _, err := digestRegularFile(opts.FirmwarePath, MaxFirmwareBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("firmware: %w", err)
	}
	result := Manifest{
		SchemaVersion:    1,
		Firmware:         Firmware{Name: filepath.Base(opts.FirmwarePath), SHA256: digest, Size: n},
		ExtractionStatus: "not_provided",
		Files:            make([]File, 0),
	}
	if opts.ExtractedRoot == "" {
		return result, nil
	}
	root, err := filepath.Abs(opts.ExtractedRoot)
	if err != nil {
		return Manifest{}, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return Manifest{}, fmt.Errorf("extraction root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, errors.New("extraction root must be a real directory, not a symlink")
	}
	entries := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > MaxDirectoryEntries {
			return errors.New("directory entry limit exceeded")
		}
		if path == root {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink rejected: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular entry rejected: %s", path)
		}
		if result.InventoryTotals.Files >= MaxInventoryFiles {
			return errors.New("file count limit exceeded")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// WalkDir does not follow symlinks. Explicitly reject traversals too.
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("path outside extraction root: %s", path)
		}
		hash, size, prefix, err := digestRegularFile(path, MaxFileBytes)
		if err != nil {
			return fmt.Errorf("inventory %q: %w", rel, err)
		}
		if size > MaxInventoryBytes-result.InventoryTotals.Bytes {
			return errors.New("inventory byte limit exceeded")
		}
		result.Files = append(result.Files, File{
			Path: filepath.ToSlash(rel), SHA256: hash, Size: size,
			Classification: classify(rel, prefix),
		})
		result.InventoryTotals.Files++
		result.InventoryTotals.Bytes += size
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("extraction inventory: %w", err)
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	result.ExtractionStatus = "externally_supplied_unverified"
	return result, nil
}

func digestRegularFile(path string, limit int64) (string, int64, []byte, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return "", 0, nil, err
	}
	if !li.Mode().IsRegular() {
		return "", 0, nil, errors.New("only regular non-symlink files are supported")
	}
	if li.Size() > limit {
		return "", 0, nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", 0, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(li, opened) {
		return "", 0, nil, errors.New("file changed while opening")
	}
	h := sha256.New()
	var prefix [64]byte
	pn, err := io.ReadFull(f, prefix[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", 0, nil, err
	}
	if _, err = h.Write(prefix[:pn]); err != nil {
		return "", 0, nil, err
	}
	remaining, err := io.Copy(h, io.LimitReader(f, limit-int64(pn)+1))
	if err != nil {
		return "", 0, nil, err
	}
	total := int64(pn) + remaining
	if total > limit {
		return "", 0, nil, errors.New("file grew beyond byte limit")
	}
	after, err := f.Stat()
	if err != nil {
		return "", 0, nil, err
	}
	if !os.SameFile(opened, after) || after.Size() != total || !opened.ModTime().Equal(after.ModTime()) {
		return "", 0, nil, errors.New("file modified during hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), total, prefix[:pn], nil
}

// WriteNew writes an indented manifest without overwriting existing evidence.
// The directory containing the destination is operator-controlled/trusted.
func WriteNew(path string, m Manifest) error {
	if path == "" {
		return errors.New("output path is required")
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".firmware-researcher-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Link is atomic and exclusive: an existing destination is never replaced.
	if err := os.Link(tmp.Name(), path); err != nil {
		return fmt.Errorf("cannot create output (already exists or unsupported filesystem): %w", err)
	}
	return nil
}
