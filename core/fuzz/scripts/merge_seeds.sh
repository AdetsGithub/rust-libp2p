#!/usr/bin/env bash
# Copy hand-written seeds/ into corpus/ without clobbering fuzzer-grown inputs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

merge_one() {
  local target="$1"
  local src="seeds/${target}"
  local dst="corpus/${target}"
  if [[ ! -d "$src" ]]; then
    echo "skip (no seeds): $target" >&2
    return 0
  fi
  mkdir -p "$dst"
  local n=0
  for f in "$src"/*; do
    [[ -f "$f" ]] || continue
    local base
    base="$(basename "$f")"
    if [[ ! -e "$dst/$base" ]]; then
      cp --update=none "$f" "$dst/$base"
      n=$((n + 1))
    fi
  done
  echo "merged $n new seeds → $dst"
}

if [[ $# -eq 0 ]]; then
  for d in seeds/*/ ; do
    [[ -d "$d" ]] || continue
    merge_one "$(basename "$d")"
  done
else
  for t in "$@"; do
    merge_one "$t"
  done
fi
