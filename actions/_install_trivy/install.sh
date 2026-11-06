#!/usr/bin/env bash
# Usage: install.sh <trivy version tag, e.g. v0.75.0> <target directory>
# Downloads the Linux release archive of Trivy and installs the binary into the target directory.
# The archive is checked against the checksums file of the same release.
set -euo pipefail

version="$1"
dir="$2"

case "$(uname -m)" in
  x86_64) arch=Linux-64bit ;;
  aarch64 | arm64) arch=Linux-ARM64 ;;
  *) echo "::error::unsupported architecture $(uname -m)"; exit 1 ;;
esac
ver="${version#v}"
archive="trivy_${ver}_${arch}.tar.gz"
base="https://github.com/aquasecurity/trivy/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl --fail --silent --show-error --location --retry 3 --output "$tmp/$archive" "$base/$archive"
curl --fail --silent --show-error --location --retry 3 --output "$tmp/checksums.txt" "$base/trivy_${ver}_checksums.txt"
# only the line of this archive; a missing line fails
grep -F "  $archive" "$tmp/checksums.txt" > "$tmp/archive.sha256" \
  || { echo "::error::no checksum for $archive in the release"; exit 1; }
(cd "$tmp" && sha256sum --check archive.sha256)
mkdir -p "$dir"
tar --extract --gzip --file "$tmp/$archive" --directory "$dir" trivy
