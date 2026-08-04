#!/usr/bin/env bash
# Provision the Dagger CLI at exactly the version the module requires.
#
# `dagger.json`'s `engineVersion` is the single source of truth for the
# Dagger version across this repo (SDK in dagger/go.mod, CLI here, CI
# workflows). A module refuses to run on a CLI older than its
# engineVersion, so deriving the CLI version from that file — rather than
# pinning it a second time — makes drift structurally impossible.
#
# The CLI is not `go install`-able (dagger.io/dagger is the SDK library;
# the CLI lives in the engine monorepo and ships as prebuilt binaries),
# and Dagger downloads its engine as an OCI image at runtime anyway, so
# fetching the binary costs nothing in reproducibility terms. We do NOT
# pipe a remote installer into a shell: the tarball is downloaded, its
# SHA-256 is checked against the release's own checksums.txt, and only
# then is it unpacked.
#
# Downloads land in a per-version cache and are reused, so the common
# path is a single `test -x`. Prints the directory holding the binary on
# stdout (for PATH); all logging goes to stderr.
set -euo pipefail

# Resolve the repo root. `git` first because the flake's shellHook runs
# this script from the Nix store (where $0's parent is a store path, not
# the checkout); the $0-relative fallback keeps direct invocation working
# outside a git checkout.
if [ -n "${DAGGER_CLI_REPO_ROOT:-}" ]; then
  repo_root=$DAGGER_CLI_REPO_ROOT
elif repo_root=$(git rev-parse --show-toplevel 2>/dev/null) && [ -n "$repo_root" ]; then
  :
else
  repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fi
manifest="${repo_root}/dagger.json"

[ -r "$manifest" ] || { echo "dagger-cli: missing $manifest" >&2; exit 1; }

# Extract "engineVersion": "vX.Y.Z" without requiring jq — this runs from
# the flake's shellHook, before any project tooling is guaranteed present.
version=$(sed -n 's/.*"engineVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)
[ -n "$version" ] || { echo "dagger-cli: no engineVersion in $manifest" >&2; exit 1; }

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) echo "dagger-cli: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "dagger-cli: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}/x509-certificate-exporter/dagger"
target_dir="${cache_root}/${version}-${os}-${arch}"
target_bin="${target_dir}/dagger"

# Fast path: already provisioned. Keeps `nix develop` instant and works
# offline once the cache is warm.
if [ -x "$target_bin" ]; then
  printf '%s\n' "$target_dir"
  exit 0
fi

tarball="dagger_${version}_${os}_${arch}.tar.gz"
base_url="https://github.com/dagger/dagger/releases/download/${version}"

echo "dagger-cli: provisioning ${version} (${os}/${arch})" >&2

tmp=$(mktemp -d)
# shellcheck disable=SC2064 # expand tmp now, not at trap time
trap "rm -rf '$tmp'" EXIT

curl -fsSL --retry 3 -o "${tmp}/${tarball}" "${base_url}/${tarball}"
curl -fsSL --retry 3 -o "${tmp}/checksums.txt" "${base_url}/checksums.txt"

expected=$(awk -v f="$tarball" '$2 == f || $2 == "*" f { print $1 }' "${tmp}/checksums.txt" | head -n1)
[ -n "$expected" ] || { echo "dagger-cli: ${tarball} absent from checksums.txt" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "${tmp}/${tarball}" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "${tmp}/${tarball}" | cut -d' ' -f1)
fi

if [ "$actual" != "$expected" ]; then
  echo "dagger-cli: checksum mismatch for ${tarball}" >&2
  echo "  expected ${expected}" >&2
  echo "  actual   ${actual}" >&2
  exit 1
fi

tar -xzf "${tmp}/${tarball}" -C "$tmp" dagger
chmod +x "${tmp}/dagger"

# Publish atomically: a concurrent shell either sees no dir or a complete
# one, never a half-extracted binary.
mkdir -p "$cache_root"
staging=$(mktemp -d "${cache_root}/.staging-XXXXXX")
mv "${tmp}/dagger" "${staging}/dagger"
mv "$staging" "$target_dir" 2>/dev/null || rm -rf "$staging"

[ -x "$target_bin" ] || { echo "dagger-cli: provisioning failed" >&2; exit 1; }
printf '%s\n' "$target_dir"
