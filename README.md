# Firmware Researcher

Evidence-first firmware research for authorized IoT security work. **Early development: ingestion foundation only.** This is a standalone project, with no AI, ReVa, or Reconductor integration yet.

## Implemented

- SHA-256 and byte-size identity for a supplied local firmware image.
- Optional deterministic, read-only inventory of an **already extracted** directory: relative paths, sizes, hashes, ELF architecture hints, and conservative file-type labels.
- Finite limits: 512 MiB firmware image, 512 MiB per inventoried file, 2 GiB aggregate extracted files, 20,000 files, 50,000 filesystem entries.
- Refuses symlinks, special files, changes detected during hashing, and output overwrites. Writes a new JSON manifest with mode 0600.
- Standard-library-only Go CLI with unit tests; no network access or firmware execution.

## Build and use

Requires Go 1.23+ on Linux.

```bash
go test ./...
go build -o researcher ./cmd/researcher
./researcher ingest --firmware ./router.bin --out ./manifest.json
# After extraction in an isolated environment and review of the output directory:
./researcher ingest --firmware ./router.bin --extracted ./unpacked --out ./manifest-with-files.json
```

`--extracted` only inventories the supplied directory; it **does not prove** that files came from the supplied firmware image or that extraction was complete. `extraction_status` is `not_provided` or `externally_supplied_unverified`. A future isolated Binwalk worker will bind extraction output to the input's digest and retain tool provenance. Do not pass sensitive firmware or secrets to hosted AI systems.

## Security boundaries and limitations

**Do not use this as a firmware sandbox.** Parsing and extraction tools should run in a disposable, network-isolated VM or equally justified containment environment. The CLI does not invoke Binwalk, run firmware binaries, start emulation, or connect to devices. It is not yet safe to treat an arbitrary untrusted extracted directory as a live workspace for other execution tools.

The scanner does not follow directory symlinks, but it is not a defense against a hostile process modifying files concurrently or swapping parent directories. Inventory roots and output directories must be controlled by the researcher and not concurrently writable by an adversary. The file classifiers are conservative hints, not proof of executable safety, privileges, or vulnerabilities.

## Next engineering milestone

Add an isolated, explicitly authorized Binwalk v3 worker with pinned dependencies, extraction budgets, and provenance, then accept its output as an attested session rather than an arbitrary directory. After end-to-end extraction fixtures pass, connect selected ELF files to a **read-only, allowlisted** ReVa/Ghidra adapter. AI hypothesis generation comes after deterministic analysis works.

No general-purpose shell execution, multi-agent framework, cloud infrastructure, or direct Reconductor database integration is planned for the MVP.
