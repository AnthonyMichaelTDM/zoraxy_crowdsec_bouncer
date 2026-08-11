#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

tmpdir=$(mktemp -d)
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ ! -f .introspect ]; then
  echo "ERROR: .introspect file is missing."
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is not installed. Install jq to validate .introspect."; exit 1; }

jq -S . .introspect > "$tmpdir/expected.json"

if ! go run . -introspect > "$tmpdir/actual_raw.json" 2> "$tmpdir/actual.stderr"; then
  echo "ERROR: failed to generate introspection output."
  echo "stdout from go run . -introspect:"
  cat "$tmpdir/actual_raw.json" || true
  echo "stderr from go run . -introspect:"
  cat "$tmpdir/actual.stderr" || true
  exit 1
fi

if [ ! -s "$tmpdir/actual_raw.json" ]; then
  echo "ERROR: introspection output was empty."
  echo "Ensure 'go run . -introspect' prints valid JSON and exits successfully."
  echo "stderr:"
  cat "$tmpdir/actual.stderr"
  exit 1
fi

jq -S . "$tmpdir/actual_raw.json" > "$tmpdir/actual.json"

if ! diff -u "$tmpdir/expected.json" "$tmpdir/actual.json" >/dev/null; then
  echo "ERROR: .introspect is out of date."
  echo "Run 'go run . -introspect > .introspect' and stage the updated file."
  exit 1
fi

echo ".introspect is up to date."
