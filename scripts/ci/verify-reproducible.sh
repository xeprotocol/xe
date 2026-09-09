#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
SRC="$PWD"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GO_VERSION="$(cat .go-version)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

A="$WORK/a"
B="$WORK/bbbbbbbbbbbbbbbbbbbb"

echo "==> source      $SRC"
echo "==> version     $VERSION"
echo "==> toolchain   go$GO_VERSION"

for dir in "$A" "$B"; do
  mkdir -p "$dir"
  tar --exclude=./.git --exclude=./dist --exclude=./data -cf - -C "$SRC" . | tar -xf - -C "$dir"
done

build() {
  local dir="$1" out="$2"
  ( cd "$dir" \
    && CGO_ENABLED=0 GOTOOLCHAIN="go${GO_VERSION}" GOCACHE="$dir/.gocache" \
       go build -trimpath -buildvcs=false \
         -ldflags "-s -w -X main.version=${VERSION}" \
         -o "$out" ./cmd/xe/ )
}

echo "==> build A ($A)"
build "$A" "$WORK/xe-a"
echo "==> build B ($B)"
build "$B" "$WORK/xe-b"

SUM_A="$(sha256sum "$WORK/xe-a" | cut -d' ' -f1)"
SUM_B="$(sha256sum "$WORK/xe-b" | cut -d' ' -f1)"
SIZE_A="$(stat -c%s "$WORK/xe-a")"
SIZE_B="$(stat -c%s "$WORK/xe-b")"

echo
echo "build A  $SUM_A  ($SIZE_A bytes)"
echo "build B  $SUM_B  ($SIZE_B bytes)"
echo

if [ "$SUM_A" = "$SUM_B" ]; then
  echo "PASS: reproducible across build paths — sha256 $SUM_A"
  exit 0
fi

echo "FAIL: the same commit produced different binaries"
if command -v cmp >/dev/null; then
  cmp -l "$WORK/xe-a" "$WORK/xe-b" | head -20 || true
fi
exit 1
