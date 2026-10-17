# Firmware Researcher

Evidence-first firmware research for authorized IoT security work. **Early development: deterministic ingestion and a Docker-isolated Binwalk extraction adapter.** No AI, ReVa, or Reconductor integration yet.

## Implemented

- `ingest`: SHA-256 and byte-size identity for a local firmware image; optional inventory of a separately extracted directory (unverified origin).
- `extract`: explicitly requested, **non-recursive** Binwalk v3.1.0 extraction inside a restricted local Docker container. The original firmware is **not** mounted: only a staged copy is passed to the worker.
- Network disabled, read-only container root, dropped capabilities, no-new-privileges, non-root UID, PID/CPU/RAM limits, 512 MiB capped scratch tmpfs, bounded stdout/stderr, 3-minute default deadline, and forced container cleanup. No shell, firmware execution, or emulation.
- Post-extraction deterministic file hashes, conservative ELF architecture and file-type hints; extracted symlinks are recorded as **unfollowed metadata**, including absolute targets. External `ingest --extracted` retains its stricter symlink rejection.
- New session folder published only on successful extraction and inventory, containing `manifest.json`, `extracted/`, `binwalk.json`, `stdout.log`, `stderr.log`. Manifest identifies the worker image ID and log hashes. Success does **not** prove comprehensive extraction or a vulnerability.
- Limits: 512 MiB firmware, 512 MiB per inventoried file, 2 GiB inventory aggregate, 20,000 files and 50,000 filesystem entries. The worker's extraction output is bounded by scratch tmpfs; post-extraction limits fail closed.

## Build

Requires Linux, Go 1.23+, Git, and a **trusted local Docker Engine** (Docker Desktop not required). The Docker image is built from the upstream Binwalk v3.1.0 commit `4fdab3d464d97b68e0af9088df3f9e2e1545b21c`. The upstream image build installs Binwalk's extraction dependencies and may use substantial bandwidth and disk space.

```bash
go test -race ./...
go vet ./...
go build -o researcher ./cmd/researcher
bash scripts/build-binwalk-worker.sh
```

Review the pinned upstream Dockerfile and its dependencies before building. The script checks out the exact upstream commit, then builds local image `firmware-researcher-binwalk:v3.1.0`. The default image tag assumes the local image was built from the pinned source; the manifest also records the actual Docker image ID. A digest-pinned image reference may be supplied with `--image`.

## OWASP IoTGoat extraction (Fedora)

The input is the already-downloaded 33 MB lab image at `~/Research/IoTGoat/IoTGoat-raspberry-pi2.img`.

```bash
./researcher extract \
  --firmware "$HOME/Research/IoTGoat/IoTGoat-raspberry-pi2.img" \
  --out-dir "$HOME/Research/IoTGoat/extraction-01"

python3 -m json.tool "$HOME/Research/IoTGoat/extraction-01/manifest.json" | less
```

`--out-dir` must not exist; create a fresh name for each attempt. `--timeout 5m` can be used for a slower system, up to 15 minutes. The parent directory must already exist. Extracted files must be treated as untrusted data; do not execute them or follow recorded symlinks. No data is sent to an AI provider or external network by this application.

For firmware identity without Docker:

```bash
./researcher ingest --firmware ./router.bin --out ./manifest.json
```

For a previously extracted directory (without verified provenance):

```bash
./researcher ingest --firmware ./router.bin --extracted ./unpacked --out ./manifest-with-files.json
```

## Important isolation limits

Docker is a **container boundary**, not a guarantee against kernel exploits. Its daemon is trusted, and running Docker generally grants powerful privileges on the host. Prefer a separate disposable VM for unknown or actively hostile firmware. The host-side Docker copy/export mechanism and native file inventory are not a formally verified hostile-archive security boundary. Do not enable `--privileged`, host networking, bind mounts of your home/development directories, Docker socket mounts, or arbitrary extractor command flags.

The worker never executes extracted firmware. However Binwalk may invoke **its own external unpacking utilities** inside the restricted container. Non-recursive extraction can miss nested payloads or unsupported formats. Successful extraction means only that the worker reported an exit code of zero and yielded files. `coverage_verified` remains false.

Normal unit tests use a fake Docker interface to verify command restrictions, successful evidence publication, cleanup, and fail-closed handling. **A real Docker/Binwalk/IoTGoat integration run must be performed on the user's lab machine**; CI does not claim to have executed the full extractor chain.

The inventory API does not defend against a hostile, concurrent host process swapping extracted files or their parent directories during hashing. Keep output directories under the researcher's control. If extraction fails, staging output is removed and the destination is not published; errors appear on stderr.

## Next milestone

Validate the real IoTGoat run and its recovered filesystem and evaluate the limits. Once repeatable, connect selected ELF files through a read-only, allowlisted ReVa adapter. AI comes after deterministic analysis.

## ReVa first ARM integration (development, unverified on real Ghidra)

`reva-overview` is a narrow, operator-initiated adapter. It selects **one unique ELF basename** from a successful extracted-session manifest, rechecks its bytes against the recorded SHA-256, and starts a trusted local `mcp-reva` in a disposable Ghidra project. Only two MCP tools are invoked: `import-file` (mutates the **disposable Ghidra project**, not the ELF), then the read-only `get-program-overview` tool from the ReVa static-analysis expansion. It rejects absent/mismatched Ghidra SHA-256 and never calls PyGhidra scripts, shells, or arbitrary tools. No AI model is connected.

This requires your separately installed and verified **development ReVa expansion** (with `get-program-overview`), a working headless `mcp-reva` executable, and `GHIDRA_INSTALL_DIR` pointing at the intended Ghidra installation. Do not modify your stable Ghidra or persistent ReVa workspace to test this integration.

```bash
export GHIDRA_INSTALL_DIR=/path/to/verified/development/ghidra
command -v mcp-reva # must resolve to your verified development environment
./researcher reva-overview \
  --session "$HOME/Research/IoTGoat/extraction-05" \
  --name uhttpd \
  --out "$HOME/Research/IoTGoat/reva-uhttpd-overview-01.json" \
  --timeout 8m
```

To use a development virtualenv without changing PATH, pass `--reva-bin /absolute/path/to/venv/bin/mcp-reva`. Each run creates and cleans up a temporary headless Ghidra project. If the target's filename is ambiguous or the ReVa extension isn't installed in that environment, it fails closed. Overview evidence records hashes and returned Ghidra metadata but **does not prove security vulnerabilities or validate ARM data-flow capabilities**. A real ARM/Ghidra smoke test remains required before adding CFG/P-code investigations.
