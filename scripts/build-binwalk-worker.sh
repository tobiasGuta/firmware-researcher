#!/usr/bin/env bash
set -euo pipefail

# Builds the verified upstream Binwalk v3.1.0 Dockerfile from its pinned commit.
# This contacts GitHub and may download significant build dependencies.
ref='4fdab3d464d97b68e0af9088df3f9e2e1545b21c'
tag='firmware-researcher-binwalk:v3.1.0'
source_dir="$(mktemp -d)"
trap 'rm -rf "$source_dir"' EXIT

git clone --quiet https://github.com/ReFirmLabs/binwalk.git "$source_dir"
git -C "$source_dir" checkout --quiet --detach "$ref"
actual="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$actual" == "$ref" ]] || { echo 'Pinned Binwalk revision mismatch' >&2; exit 1; }

docker build --tag "$tag" "$source_dir"
docker image inspect --format '{{.Id}}' "$tag"
printf 'Built %s from upstream commit %s\n' "$tag" "$ref"
