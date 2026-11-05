#!/bin/sh
# Builds the browser/PWA phone side: sdk/web/dist/tailpocket.wasm and Go's wasm_exec.js next to it.
set -eu
cd "$(dirname "$0")/.."
mkdir -p sdk/web/dist
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -tags ts_omit_ssh -o sdk/web/dist/tailpocket.wasm ./cmd/tailpocket-wasm
install -m 644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" sdk/web/dist/wasm_exec.js # GOROOT copies are read-only
echo "built sdk/web/dist"
