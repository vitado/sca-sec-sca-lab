#!/usr/bin/env bash
# Usage: install.sh check <trivy version tag>
#        install.sh <trivy version tag, e.g. v0.75.0> <target directory>
# Environment: TRIVY_SHA256 (optional), the sha256 of the release archive of this runner's architecture.
#
# "check" only validates the version tag. The other form puts the Trivy binary into the target
# directory. The sha256 of the archive is pinned here per version (taken from the official release
# checksums); the checksums file of the release is not trusted by itself. A version that is not in
# the table needs TRIVY_SHA256. The target directory is a cache: it keeps the verified archive, and
# the archive found there is verified again and unpacked again, so a restored cache is not trusted.
set -euo pipefail

version="${2:-}"
[ "$1" = check ] || version="$1"
if ! [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::trivy-version must be a release tag of the form vX.Y.Z (for example v0.75.0), got '$version'"
  exit 1
fi
[ "$1" = check ] && exit 0
dir="$2"

case "$(uname -m)" in
  x86_64) arch=Linux-64bit ;;
  aarch64 | arm64) arch=Linux-ARM64 ;;
  *) echo "::error::unsupported architecture $(uname -m)"; exit 1 ;;
esac
ver="${version#v}"
archive="trivy_${ver}_${arch}.tar.gz"

# pinned sha256 of the release archives: <version>/<arch>
case "$version/$arch" in
  v0.75.0/Linux-64bit) sha256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f ;;
  v0.75.0/Linux-ARM64) sha256=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3 ;;
  *) sha256="${TRIVY_SHA256:-}" ;;
esac
if [ -z "$sha256" ]; then
  echo "::error::no pinned sha256 for Trivy $version ($arch): pass the sha256 of $archive as the trivy-sha256 input"
  exit 1
fi

mkdir -p "$dir"
if [ -f "$dir/$archive" ] && echo "$sha256  $dir/$archive" | sha256sum --check --status -; then
  echo "using the cached archive $archive"
else
  rm -f "$dir/$archive"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl --fail --silent --show-error --location --retry 3 --output "$tmp/$archive" \
    "https://github.com/aquasecurity/trivy/releases/download/$version/$archive"
  echo "$sha256  $tmp/$archive" | sha256sum --check - \
    || { echo "::error::sha256 of $archive does not match the pinned value"; exit 1; }
  mv "$tmp/$archive" "$dir/$archive"
fi
tar --extract --gzip --file "$dir/$archive" --directory "$dir" trivy
