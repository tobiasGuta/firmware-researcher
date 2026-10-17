package reva

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobiasGuta/firmware-researcher/internal/ingest"
)

const maxManifestBytes = 16 << 20

type Target struct {
	Session        string `json:"session"`
	FirmwareSHA256 string `json:"firmware_sha256"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size_bytes"`
	Architecture   string `json:"architecture"`
	LocalPath      string `json:"-"`
}

// Select verifies a named ELF against the existing extraction inventory before
// it can be imported by the trusted local ReVa process. Ambiguity fails closed.
func Select(session, name string) (Target, error) {
	if session == "" || name == "" || name == "." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return Target{}, errors.New("session and a single filename (for example uhttpd) are required")
	}
	root, err := filepath.Abs(session)
	if err != nil {
		return Target{}, err
	}
	if err := checkDirectory(root); err != nil {
		return Target{}, fmt.Errorf("session directory: %w", err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := checkRegular(manifestPath); err != nil {
		return Target{}, err
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return Target{}, err
	}
	defer f.Close()
	var m ingest.Manifest
	d := json.NewDecoder(io.LimitReader(f, maxManifestBytes+1))
	if err := d.Decode(&m); err != nil {
		return Target{}, fmt.Errorf("invalid manifest: %w", err)
	}
	if m.SchemaVersion != 1 || m.ExtractionStatus != "isolated_binwalk_success_unverified_coverage" || m.Extraction == nil || m.Extraction.Engine != "binwalk" {
		return Target{}, errors.New("requires a successful, provenance-bearing isolated extraction manifest")
	}
	if len(m.Firmware.SHA256) != 64 {
		return Target{}, errors.New("manifest firmware identity missing")
	}
	var match *ingest.File
	for i := range m.Files {
		file := &m.Files[i]
		if filepath.Base(file.Path) == name && file.Kind == "elf" {
			if match != nil {
				return Target{}, fmt.Errorf("ambiguous ELF filename %q; refusing selection", name)
			}
			match = file
		}
	}
	if match == nil {
		return Target{}, fmt.Errorf("no inventoried ELF named %q", name)
	}
	if match.Architecture != "arm" && match.Architecture != "aarch64" && match.Architecture != "mips" && match.Architecture != "x86" && match.Architecture != "x86_64" && match.Architecture != "riscv" && match.Architecture != "powerpc" {
		return Target{}, fmt.Errorf("unrecognized ELF architecture %q", match.Architecture)
	}
	// Manifest paths are POSIX-style and must remain underneath extracted/.
	clean := filepath.Clean(filepath.FromSlash(match.Path))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.ToSlash(clean) != match.Path {
		return Target{}, errors.New("unsafe component path in manifest")
	}
	extraction := filepath.Join(root, "extracted")
	if err := checkDirectory(extraction); err != nil {
		return Target{}, err
	}
	candidate := filepath.Join(extraction, clean)
	if err := checkNoSymlinkPath(extraction, candidate); err != nil {
		return Target{}, err
	}
	hash, size, err := digest(candidate, ingest.MaxFileBytes)
	if err != nil {
		return Target{}, err
	}
	if hash != match.SHA256 || size != match.Size {
		return Target{}, errors.New("component bytes differ from extraction manifest")
	}
	return Target{Session: root, FirmwareSHA256: m.Firmware.SHA256, Path: match.Path, SHA256: hash, Size: size, Architecture: match.Architecture, LocalPath: candidate}, nil
}

func checkRegular(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}
	return nil
}
func checkDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("not a real directory: %s", path)
	}
	return nil
}
func checkNoSymlinkPath(root, full string) error {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("component escaped extraction root")
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, p := range parts {
		current = filepath.Join(current, p)
		st, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in selected component path: %s", current)
		}
		if i < len(parts)-1 && !st.IsDir() {
			return fmt.Errorf("not a directory: %s", current)
		}
		if i == len(parts)-1 && !st.Mode().IsRegular() {
			return fmt.Errorf("not a regular component: %s", current)
		}
	}
	return nil
}
func digest(path string, limit int64) (string, int64, error) {
	if err := checkRegular(path); err != nil {
		return "", 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return "", 0, errors.New("component is not regular or exceeds limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	after, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if n > limit || after.Size() != n || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, errors.New("component changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
