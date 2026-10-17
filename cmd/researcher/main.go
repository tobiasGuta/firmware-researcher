package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobiasGuta/firmware-researcher/internal/ingest"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println(usage())
		return nil
	}
	if len(args) == 0 || args[0] != "ingest" {
		return errors.New(usage())
	}
	flags := flag.NewFlagSet("ingest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	firmware := flags.String("firmware", "", "local firmware image (required)")
	extracted := flags.String("extracted", "", "optional directory extracted separately in an isolated environment")
	output := flags.String("out", "", "new JSON manifest output path (required; never overwritten)")
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
			return errors.New("output must be outside the extracted directory")
		}
	}
	m, err := ingest.Generate(ingest.Options{FirmwarePath: *firmware, ExtractedRoot: *extracted})
	if err != nil {
		return err
	}
	if err := ingest.WriteNew(*output, m); err != nil {
		return err
	}
	fmt.Printf("firmware sha256: %s\ninventoried files: %d\nextraction status: %s\nmanifest: %s\n", m.Firmware.SHA256, len(m.Files), m.ExtractionStatus, *output)
	return nil
}

func usage() string {
	return `Usage: researcher ingest --firmware IMAGE --out MANIFEST.json [--extracted DIRECTORY]

Offline, read-only inventory. --extracted accepts an existing directory prepared
in an external isolated worker; this tool does not execute Binwalk or extract
firmware. Never run unknown firmware unpackers directly on your workstation.`
}
