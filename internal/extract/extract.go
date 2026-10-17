// Package extract performs one non-recursive Binwalk run in a restricted Docker
// container. It stages a firmware copy; no original host directory is mounted
// inside the worker. Docker itself must be a trusted, current local daemon.
package extract

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/firmware-researcher/internal/ingest"
)

const (
	DefaultImage         = "firmware-researcher-binwalk:v3.1.0"
	BinwalkVersion       = "v3.1.0"
	maxStagedBytes       = ingest.MaxFirmwareBytes
	maxOutputLogBytes    = 128 << 10
	maxSignatureLogBytes = 16 << 20
	// Tmpfs prevents the extractor from filling the host's ordinary filesystem.
	scratchBytes = 512 << 20
)

// Options identifies one firmware source and a new, not-yet-existing output
// directory. Parent directories are trusted, operator-controlled paths.
type Options struct {
	Firmware  string
	OutputDir string
	Image     string
	Timeout   time.Duration
}

type Runner interface {
	Run(ctx context.Context, args ...string) (string, string, error)
}

type Docker struct{}

// limitedBuffer records only bounded diagnostics; overflow is discarded while
// the subprocess is reaped, not kept in RAM.
type limitedBuffer struct {
	data []byte
	max  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - len(b.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *limitedBuffer) String() string { return string(b.data) }

func (Docker) Run(ctx context.Context, args ...string) (string, string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	stdout, stderr := &limitedBuffer{max: maxOutputLogBytes}, &limitedBuffer{max: maxOutputLogBytes}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func Run(ctx context.Context, opts Options) (ingest.Manifest, error) {
	return RunWith(ctx, opts, Docker{})
}

// RunWith is injectable so the Docker execution contract can be tested without
// running untrusted tooling or requiring a daemon in ordinary Go unit tests.
func RunWith(ctx context.Context, opts Options, docker Runner) (ingest.Manifest, error) {
	if opts.Firmware == "" || opts.OutputDir == "" {
		return ingest.Manifest{}, errors.New("firmware and output directory are required")
	}
	if opts.Image == "" {
		opts.Image = DefaultImage
	}
	if opts.Image != DefaultImage && !strings.Contains(opts.Image, "@sha256:") {
		return ingest.Manifest{}, errors.New("worker image must be the pinned default tag or a digest-pinned image")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Minute
	}
	if opts.Timeout < time.Second || opts.Timeout > 15*time.Minute {
		return ingest.Manifest{}, errors.New("timeout must be between 1 second and 15 minutes")
	}
	if ctx.Err() != nil {
		return ingest.Manifest{}, ctx.Err()
	}
	src, err := filepath.Abs(opts.Firmware)
	if err != nil {
		return ingest.Manifest{}, err
	}
	dest, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return ingest.Manifest{}, err
	}
	parent := filepath.Dir(dest)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return ingest.Manifest{}, fmt.Errorf("output parent: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return ingest.Manifest{}, errors.New("output parent must be a real directory")
	}
	if _, err := os.Lstat(dest); err == nil {
		return ingest.Manifest{}, errors.New("output directory already exists")
	} else if !os.IsNotExist(err) {
		return ingest.Manifest{}, err
	}
	initial, err := ingest.Generate(ingest.Options{FirmwarePath: src})
	if err != nil {
		return ingest.Manifest{}, err
	}
	if initial.Firmware.Size == 0 {
		return ingest.Manifest{}, errors.New("empty firmware is not supported")
	}
	stage, err := os.MkdirTemp(parent, ".firmware-researcher-")
	if err != nil {
		return ingest.Manifest{}, err
	}
	defer os.RemoveAll(stage)
	input := filepath.Join(stage, "firmware.img")
	if err = stageInput(src, input, initial.Firmware); err != nil {
		return ingest.Manifest{}, err
	}
	workerCtx, workerCancel := context.WithTimeout(ctx, opts.Timeout)
	defer workerCancel()
	imageStdout, imageStderr, err := docker.Run(workerCtx, "image", "inspect", "--format", "{{.Id}}", opts.Image)
	if err != nil {
		return ingest.Manifest{}, fmt.Errorf("worker image missing (build the pinned Binwalk worker first): %v: %s", err, imageStderr)
	}
	imageID := strings.TrimSpace(imageStdout)
	if !strings.HasPrefix(imageID, "sha256:") || len(imageID) != 71 {
		return ingest.Manifest{}, errors.New("docker image inspect returned invalid image ID")
	}
	token, err := uniqueToken()
	if err != nil {
		return ingest.Manifest{}, err
	}
	name := "firmware-researcher-" + token
	createArgs := dockerCreateArgs(name, opts.Image, input)
	createOut, createErr, err := docker.Run(workerCtx, createArgs...)
	if err != nil {
		return ingest.Manifest{}, fmt.Errorf("docker create failed: %v: %s", err, createErr)
	}
	if strings.TrimSpace(createOut) == "" {
		return ingest.Manifest{}, errors.New("docker create returned empty container ID")
	}
	// Every exit after container creation, including timeouts, tries to kill and
	// remove the worker using a fresh context independent of the run deadline.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _, _ = docker.Run(cleanupCtx, "rm", "-f", name)
	}()
	stdout, stderr, err := docker.Run(workerCtx, "start", "--attach", name)
	if err != nil {
		return ingest.Manifest{}, fmt.Errorf("binwalk worker failed or timed out: %v: %s", err, stderr)
	}
	state, stateErr, err := docker.Run(workerCtx, "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name)
	if err != nil {
		return ingest.Manifest{}, fmt.Errorf("cannot verify worker exit status: %v: %s", err, stateErr)
	}
	if strings.TrimSpace(state) != "false 0" {
		return ingest.Manifest{}, fmt.Errorf("worker did not exit successfully (state %q): %s", strings.TrimSpace(state), stderr)
	}
	extracted := filepath.Join(stage, "extracted")
	if err = os.Mkdir(extracted, 0700); err != nil {
		return ingest.Manifest{}, err
	}
	if _, e, err := docker.Run(workerCtx, "cp", name+":/scratch/extracted/.", extracted); err != nil {
		return ingest.Manifest{}, fmt.Errorf("no extractable content or docker cp failed: %v: %s", err, e)
	}
	if _, e, err := docker.Run(workerCtx, "cp", name+":/scratch/binwalk.json", filepath.Join(stage, "binwalk.json")); err != nil {
		return ingest.Manifest{}, fmt.Errorf("binwalk JSON provenance unavailable: %v: %s", err, e)
	}
	info, err := os.Lstat(filepath.Join(stage, "binwalk.json"))
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSignatureLogBytes {
		return ingest.Manifest{}, errors.New("binwalk JSON provenance absent, non-regular or oversized")
	}
	if err = os.WriteFile(filepath.Join(stage, "stdout.log"), []byte(stdout), 0600); err != nil {
		return ingest.Manifest{}, err
	}
	if err = os.WriteFile(filepath.Join(stage, "stderr.log"), []byte(stderr), 0600); err != nil {
		return ingest.Manifest{}, err
	}
	manifest, err := ingest.Generate(ingest.Options{FirmwarePath: src, ExtractedRoot: extracted, RecordSymlinks: true})
	if err != nil {
		return ingest.Manifest{}, err
	}
	if manifest.InventoryTotals.Files == 0 {
		return ingest.Manifest{}, errors.New("extraction yielded no regular files")
	}
	finalInput, err := ingest.Generate(ingest.Options{FirmwarePath: src})
	if err != nil {
		return ingest.Manifest{}, err
	}
	if finalInput.Firmware != initial.Firmware {
		return ingest.Manifest{}, errors.New("original firmware changed during extraction")
	}
	manifest.ExtractionStatus = "isolated_binwalk_success_unverified_coverage"
	signatures, err := os.ReadFile(filepath.Join(stage, "binwalk.json"))
	if err != nil {
		return ingest.Manifest{}, err
	}
	logHash := sha256.Sum256(signatures)
	outHash := sha256.Sum256([]byte(stdout))
	errHash := sha256.Sum256([]byte(stderr))
	manifest.Extraction = &ingest.Extraction{
		Engine: "binwalk", Version: BinwalkVersion, ImageRef: opts.Image, ImageID: imageID,
		SignatureLog: "binwalk.json", SignatureSHA256: hex.EncodeToString(logHash[:]),
		StdoutLog: "stdout.log", StdoutSHA256: hex.EncodeToString(outHash[:]),
		StderrLog: "stderr.log", StderrSHA256: hex.EncodeToString(errHash[:]),
		WorkerNetwork: "none", CoverageVerified: false,
	}
	if err = ingest.WriteNew(filepath.Join(stage, "manifest.json"), manifest); err != nil {
		return ingest.Manifest{}, err
	}
	if err = os.Remove(input); err != nil {
		return ingest.Manifest{}, err
	}
	if err = os.Rename(stage, dest); err != nil {
		return ingest.Manifest{}, fmt.Errorf("publication failed: %w", err)
	}
	return manifest, nil
}

func dockerCreateArgs(name, image, input string) []string {
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 65534, 65534
	} // Never run the worker as container root.
	return []string{
		"create", "--name", name,
		"--label", "org.firmware-researcher.worker=binwalk",
		"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=64", "--cpus=2", "--memory=1536m", "--memory-swap=1536m",
		"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
		"--tmpfs=/scratch:rw,nosuid,nodev,size=" + strconv.FormatInt(scratchBytes, 10) + ",mode=1777",
		"--workdir=/scratch", "--env=BINWALK_RM_EXTRACTION_SYMLINK=1",
		// :Z labels ONLY the private staged firmware copy on SELinux systems.
		"--volume=" + input + ":/analysis/firmware.img:ro,Z",
		"--entrypoint=binwalk", image,
		"--extract", "--threads=2", "--directory=/scratch/extracted", "--log=/scratch/binwalk.json", "/analysis/firmware.img",
	}
}

func stageInput(src, dest string, expected ingest.Firmware) error {
	li, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !li.Mode().IsRegular() {
		return errors.New("firmware source is not regular")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(li, opened) {
		return errors.New("firmware source changed while opening")
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, maxStagedBytes+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if n != expected.Size {
		return errors.New("firmware size changed while staging")
	}
	current, err := ingest.Generate(ingest.Options{FirmwarePath: dest})
	if err != nil {
		return err
	}
	if current.Firmware.SHA256 != expected.SHA256 {
		return errors.New("firmware bytes changed while staging")
	}
	if err = os.Chmod(dest, 0444); err != nil {
		return err
	}
	return nil
}

func uniqueToken() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
