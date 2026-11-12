#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT="${1:-client-android-arm64}"

echo "Building Android ARM64 PIE binary -> $SCRIPT_DIR/$OUT ..."
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
    go build -buildmode=pie -ldflags="-s -w" -o "$OUT" .

echo "Done: $(ls -lh "$OUT")"
