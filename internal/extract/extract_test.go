package extract

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeDocker struct {
	calls  [][]string
	failOn string
	noFiles bool
}

func (f *fakeDocker) Run(_ context.Context, args ...string) (string, string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) == 0 {
		panic("empty args")
	}
	if args[0] == f.failOn {
		return "", "simulated failure", errors.New("fake docker failed")
	}
	switch args[0] {
	case "image":
		return "sha256:" + strings.Repeat("a", 64) + "\n", "", nil
	case "create":
		return "fake-container-id\n", "", nil
	case "start":
		return "fake-container-id\n", "", nil
	case "exec":
		return "0\n", "", nil
	case "logs":
		return "signature found\n", "diagnostics\n", nil
	case "inspect":
		return "true 0\n", "", nil
	case "cp":
		if len(args) != 3 {
			panic("bad cp arguments")
		}
		if strings.HasSuffix(args[1], "/scratch/extracted/.") {
			if f.noFiles {
				return "", "Could not find the file /scratch/extracted/. in container", errors.New("exit status 1")
			}
			root := args[2]
			if err := os.MkdirAll(filepath.Join(root, "squashfs-root/bin"), 0700); err != nil {
				return "", "", err
			}
			if err := os.WriteFile(filepath.Join(root, "squashfs-root/bin/busybox"), []byte("ELF example"), 0600); err != nil {
				return "", "", err
			}
			if err := os.Symlink("/bin/busybox", filepath.Join(root, "squashfs-root/bin/ash")); err != nil {
				return "", "", err
			}
			if err := os.Symlink("../../../../etc/passwd", filepath.Join(root, "squashfs-root/bin/escape")); err != nil {
				return "", "", err
			}
		} else if strings.HasSuffix(args[1], "/scratch/binwalk.json") {
			if err := os.WriteFile(args[2], []byte(`{"results":[]}`), 0600); err != nil {
				return "", "", err
			}
		} else {
			panic("unexpected cp source: " + args[1])
		}
		return "", "", nil
	case "rm":
		return "", "", nil
	default:
		panic("unexpected docker command: " + args[0])
	}
}

func setup(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	image := filepath.Join(root, "sample.img")
	if err := os.WriteFile(image, []byte("example firmware"), 0600); err != nil {
		t.Fatal(err)
	}
	return image, filepath.Join(root, "new-run")
}

func TestExtractEndToEndWithFakeDocker(t *testing.T) {
	firmware, dest := setup(t)
	fake := &fakeDocker{}
	m, err := RunWith(context.Background(), Options{Firmware: firmware, OutputDir: dest}, fake)
	if err != nil {
		t.Fatal(err)
	}
	if m.ExtractionStatus != "isolated_binwalk_success_unverified_coverage" {
		t.Fatalf("status: %s", m.ExtractionStatus)
	}
	if m.InventoryTotals.Files != 1 || m.InventoryTotals.Symlinks != 2 {
		t.Fatalf("totals: %+v", m.InventoryTotals)
	}
	if m.Extraction == nil || m.Extraction.CoverageVerified || m.Extraction.ImageID != "sha256:"+strings.Repeat("a", 64) || m.Extraction.WorkerNetwork != "none" || len(m.Extraction.SignatureSHA256) != 64 || len(m.Extraction.StdoutSHA256) != 64 || len(m.Extraction.StderrSHA256) != 64 {
		t.Fatalf("provenance: %+v", m.Extraction)
	}
	if m.Links[0].Path != "squashfs-root/bin/ash" || m.Links[0].Target != "/bin/busybox" || m.Links[1].Path != "squashfs-root/bin/escape" {
		t.Fatalf("symlinks: %+v", m.Links)
	}
	for _, path := range []string{"manifest.json", "stdout.log", "stderr.log", "binwalk.json", "extracted/squashfs-root/bin/busybox"} {
		if _, err := os.Stat(filepath.Join(dest, path)); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "firmware.img")); !os.IsNotExist(err) {
		t.Fatal("firmware staging copy persisted")
	}
	if len(fake.calls) != 9 {
		t.Fatalf("expected image/create/start/exec/inspect/logs/cp/cp/rm; got %d: %+v", len(fake.calls), fake.calls)
	}
	create := strings.Join(fake.calls[1], " ")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=1536m", "--tmpfs=/scratch:rw", "--user ", ":/analysis/firmware.img:ro,Z", "--extract", "--threads=2", "--entrypoint=/bin/sh", "--log-driver=local"} {
		if !strings.Contains(create, want) {
			t.Errorf("create missing %q: %s", want, create)
		}
	}
	if strings.Contains(create, "--privileged") || strings.Contains(create, "--matryoshka") {
		t.Fatal("unexpected privilege or recursion")
	}
	if fake.calls[len(fake.calls)-1][0] != "rm" {
		t.Fatal("worker not cleaned up")
	}
}

func TestFailuresFailClosedAndCleanup(t *testing.T) {
	for _, which := range []string{"image", "create", "start", "cp"} {
		t.Run(which, func(t *testing.T) {
			firmware, dest := setup(t)
			f := &fakeDocker{failOn: which}
			_, err := RunWith(context.Background(), Options{Firmware: firmware, OutputDir: dest}, f)
			if err == nil {
				t.Fatal("accepted worker failure")
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatal("published failed extraction")
			}
			if which == "start" || which == "cp" {
				if f.calls[len(f.calls)-1][0] != "rm" {
					t.Fatal("container not removed")
				}
			}
		})
	}
}

func TestMissingExtractionReportsBinwalkEvidenceAndCleansUp(t *testing.T) {
	firmware, dest := setup(t)
	f := &fakeDocker{noFiles: true}
	_, err := RunWith(context.Background(), Options{Firmware: firmware, OutputDir: dest}, f)
	if err == nil {
		t.Fatal("missing extraction incorrectly succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"cannot export extracted files", "signature found", "diagnostics", "results", "Could not find the file"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing diagnostic %q from: %s", want, msg)
		}
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("failed extraction published a session")
	}
	if f.calls[len(f.calls)-1][0] != "rm" {
		t.Fatal("failed extraction did not clean up container")
	}
	if !strings.HasSuffix(f.calls[6][1], "/scratch/binwalk.json") || !strings.HasSuffix(f.calls[7][1], "/scratch/extracted/.") {
		t.Fatal("expected Binwalk diagnostics to be collected before extraction copy")
	}
}

func TestRejectBeforeDocker(t *testing.T) {
	firmware, dest := setup(t)
	tests := []struct {
		name string
		opts Options
	}{
		{"bad image", Options{Firmware: firmware, OutputDir: dest, Image: "latest"}},
		{"bad timeout", Options{Firmware: firmware, OutputDir: dest, Timeout: 16 * time.Minute}},
		{"missing firmware", Options{Firmware: "", OutputDir: dest}},
		{"missing destination", Options{Firmware: firmware}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDocker{}
			_, err := RunWith(context.Background(), tt.opts, f)
			if err == nil || len(f.calls) != 0 {
				t.Fatalf("not fail closed: %v, %v", err, f.calls)
			}
		})
	}
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{}
	if _, err := RunWith(context.Background(), Options{Firmware: firmware, OutputDir: dest}, f); err == nil || len(f.calls) != 0 {
		t.Fatal("allowed overwrite")
	}
}

func TestDockerCreateArgsNoHostExecOrNetwork(t *testing.T) {
	args := dockerCreateArgs("worker-123", DefaultImage, "/tmp/staged/input.bin")
	if args[0] != "create" {
		t.Fatalf("wrong command %v", args)
	}
	if strings.Join(args, " ") == "" {
		t.Fatal("empty")
	}
	expectedLast := []string{"-c", workerScript}
	if !reflect.DeepEqual(args[len(args)-len(expectedLast):], expectedLast) {
		t.Fatalf("unexpected binwalk flags: %v", args)
	}
}

func TestWorkerDiagnosticsEscapesControlCharactersAndBoundsSize(t *testing.T) {
	got := workerDiagnostics(strings.Repeat("a", 4000)+"\x1b", "secret\nvalue", []byte("{}"))
	if len(got) > 2900 || !strings.Contains(got, "[truncated]") || !strings.Contains(got, `secret\nvalue`) || strings.Contains(got, "\x1b") {
		t.Fatalf("unsafe or unbounded diagnostics: %q", got)
	}
}

func TestWaitForWorkerRequiresRunningSupervisor(t *testing.T) {
	f := &fakeDocker{}
	status, err := waitForWorker(context.Background(), f, "worker")
	if err != nil || status != 0 {
		t.Fatalf("expected worker result zero, got %d %v", status, err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "exec" || f.calls[1][0] != "inspect" {
		t.Fatalf("unexpected polling: %v", f.calls)
	}
}
