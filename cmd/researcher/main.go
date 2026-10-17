package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tobiasGuta/firmware-researcher/internal/extract"
	"github.com/tobiasGuta/firmware-researcher/internal/ingest"
	"github.com/tobiasGuta/firmware-researcher/internal/reva"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println(usage())
		return nil
	}
	if len(args) == 0 {
		return errors.New(usage())
	}
	switch args[0] {
	case "ingest":
		flags := flag.NewFlagSet("ingest", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		firmware := flags.String("firmware", "", "local firmware image (required)")
		extracted := flags.String("extracted", "", "optional directory extracted separately in isolation")
		output := flags.String("out", "", "new JSON manifest output (required; never overwritten)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if len(flags.Args()) != 0 {
			return errors.New("unexpected positional arguments")
		}
		if *firmware == "" || *output == "" {
			return errors.New("--firmware and --out are required")
		}
		if *extracted != "" {
			root, err := filepath.Abs(*extracted)
			if err != nil {
				return err
			}
			out, err := filepath.Abs(*output)
			if err != nil {
				return err
			}
			if out == root || strings.HasPrefix(out, root+string(filepath.Separator)) {
				return errors.New("output must be outside extracted directory")
			}
		}
		m, err := ingest.Generate(ingest.Options{FirmwarePath: *firmware, ExtractedRoot: *extracted})
		if err != nil {
			return err
		}
		if err = ingest.WriteNew(*output, m); err != nil {
			return err
		}
		fmt.Printf("firmware sha256: %s\ninventoried files: %d\nextraction status: %s\nmanifest: %s\n", m.Firmware.SHA256, len(m.Files), m.ExtractionStatus, *output)
		return nil
	case "extract":
		flags := flag.NewFlagSet("extract", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		firmware := flags.String("firmware", "", "local firmware image (required)")
		outDir := flags.String("out-dir", "", "new output directory (required; never overwritten)")
		image := flags.String("image", extract.DefaultImage, "local pinned Binwalk worker image")
		timeout := flags.Duration("timeout", 3*time.Minute, "total Docker worker timeout; 1s–15m")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if len(flags.Args()) != 0 {
			return errors.New("unexpected positional arguments")
		}
		m, err := extract.Run(ctx, extract.Options{Firmware: *firmware, OutputDir: *outDir, Image: *image, Timeout: *timeout})
		if err != nil {
			return err
		}
		fmt.Printf("firmware sha256: %s\nextracted files: %d\nrecorded symlinks: %d\nextraction status: %s\nmanifest: %s\n", m.Firmware.SHA256, m.InventoryTotals.Files, m.InventoryTotals.Symlinks, m.ExtractionStatus, filepath.Join(*outDir, "manifest.json"))
		return nil
	case "reva-overview", "reva-inspect":
		flags := flag.NewFlagSet("reva-overview", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		session := flags.String("session", "", "directory containing the extraction manifest and extracted files")
		name := flags.String("name", "", "unique inventoried ELF basename, e.g. uhttpd")
		out := flags.String("out", "", "new JSON evidence output (required, never overwritten)")
		launcher := flags.String("reva-bin", "mcp-reva", "trusted local mcp-reva executable")
		timeout := flags.Duration("timeout", 5*time.Minute, "ReVa session deadline (1s-15m)")
		function := flags.String("function", "", "optional exact Ghidra function name or entry address (reva-inspect only)")
		fullIndex := flags.Bool("full-index", false, "collect up to 512 functions in pages of 64 (reva-inspect only)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if len(flags.Args()) != 0 {
			return errors.New("unexpected positional arguments")
		}
		if *out == "" {
			return errors.New("--out is required")
		}
		target, err := reva.Select(*session, *name)
		if err != nil {
			return err
		}
		// Never write analysis artifacts inside the extracted firmware tree.
		outAbs, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		extracted := filepath.Join(target.Session, "extracted")
		if outAbs == extracted || strings.HasPrefix(outAbs, extracted+string(filepath.Separator)) {
			return errors.New("analysis output must be outside extracted firmware directory")
		}
		if args[0] == "reva-inspect" {
			inspection, err := reva.QueryInspection(ctx, target, *launcher, *function, *timeout, *fullIndex)
			if err != nil {
				return err
			}
			if err := reva.WriteInspectionNew(*out, inspection); err != nil {
				return err
			}
			fmt.Printf("component: %s\nsha256 identity verified: %t\nfunction page limit: 64\n", target.Path, inspection.Overview.IdentityVerified)
			if *function != "" {
				fmt.Printf("inspected function: %s\n", *function)
			}
			fmt.Printf("evidence: %s\n", *out)
			return nil
		}
		if *function != "" {
			return errors.New("--function requires reva-inspect")
		}
		if *fullIndex {
			return errors.New("--full-index requires reva-inspect")
		}
		evidence, err := reva.Query(ctx, target, *launcher, *timeout)
		if err != nil {
			return err
		}
		if err = reva.WriteNew(*out, evidence); err != nil {
			return err
		}
		fmt.Printf("component: %s\narchitecture: %s\nsha256 identity verified: %t\nReVa program: %s\nevidence: %s\n", target.Path, target.Architecture, evidence.IdentityVerified, evidence.ReVaProgramPath, *out)
		return nil
	default:
		return errors.New(usage())
	}
}

func usage() string {
	return `Usage:
  researcher ingest --firmware IMAGE --out MANIFEST.json [--extracted DIRECTORY]
  researcher extract --firmware IMAGE --out-dir NEW_DIRECTORY [--image IMAGE] [--timeout 3m]
  researcher reva-overview --session EXTRACTION_DIR --name ELF_BASENAME --out NEW_JSON [--reva-bin mcp-reva] [--timeout 5m]
  researcher reva-inspect --session EXTRACTION_DIR --name ELF_BASENAME --out NEW_JSON [--function GHIDRA_NAME_OR_ADDRESS] [--full-index] [--reva-bin mcp-reva] [--timeout 5m]

Ingest is offline and read-only. Extract invokes an explicitly configured
local Docker image containing pinned Binwalk v3.1.0. Extraction is non-recursive,
network-disabled, resource-limited, and inventories output without running any
extracted firmware. Requires a trusted Docker daemon and operator-owned paths.
An extractor's successful exit does not prove complete coverage of firmware.
ReVa overview imports one manifest-verified ELF into a disposable local Ghidra
project and invokes only import-file and get-program-overview through MCP.
reva-inspect lists one bounded page of functions by default, or up to 512 via
--full-index (pages of 64), and optionally inspects one CFG and entry P-code. Truncation flags are
retained. No AI, firmware execution, or persistent Ghidra project.`
}
