#!/bin/sh
# Build the embargo command from this checkout and run the atago specs in
# e2e/atago with it first on PATH. Extra arguments go to `atago run`.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v atago >/dev/null 2>&1; then
	echo "e2e: atago is not installed; go install github.com/nao1215/atago@v0.26.0" >&2
	exit 127
fi

BIN="$(mktemp -d)"
trap 'rm -rf "$BIN"' EXIT
go build -o "$BIN/" ./cmd/embargo
PATH="$BIN:$PATH" atago run "$@" e2e/atago
