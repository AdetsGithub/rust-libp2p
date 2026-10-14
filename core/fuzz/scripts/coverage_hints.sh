#!/usr/bin/env bash
# Coverage / stuckness measurement for a cargo-fuzz target.
# Requires: rustup nightly + llvm-tools-preview, cargo-fuzz.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?usage: $0 <fuzz-target> [extra libFuzzer args...]}"
shift || true
cd "$ROOT"

RUSTLIB_BIN="$(rustup which --toolchain nightly rustc | xargs dirname)/../lib/rustlib/x86_64-unknown-linux-gnu/bin"
RUSTLIB_BIN="$(cd "$RUSTLIB_BIN" && pwd)"
LLVM_COV="${LLVM_COV:-$RUSTLIB_BIN/llvm-cov}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$RUSTLIB_BIN/llvm-profdata}"

if [[ ! -x "$LLVM_PROFDATA" ]]; then
  echo "missing llvm-profdata at $LLVM_PROFDATA" >&2
  echo "install: rustup component add llvm-tools-preview --toolchain nightly" >&2
  exit 1
fi

echo "==> cargo fuzz coverage $TARGET"
ASAN_OPTIONS="${ASAN_OPTIONS:-symbolize=0}" cargo +nightly fuzz coverage "$TARGET" "$@"

PROF="coverage/${TARGET}/coverage.profdata"
BIN="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/${TARGET}"
if [[ ! -f "$PROF" || ! -x "$BIN" ]]; then
  echo "expected $PROF and $BIN" >&2
  exit 1
fi

HTML="coverage/${TARGET}/html"
HTML_FOCUS="coverage/${TARGET}/html-focus"
TEXT="coverage/${TARGET}/text"
mkdir -p "$HTML" "$HTML_FOCUS" "$TEXT"

echo "==> llvm-cov HTML (full) → $HTML"
"$LLVM_COV" show "$BIN" \
  -instr-profile="$PROF" \
  -format=html \
  -output-dir="$HTML" \
  2>/dev/null || true

# Focus HTML/sources by target family.
FOCUS_FILES=()
REPORT_RG='fuzz_targets'
ERR_SCAN_FILE=""
case "$TARGET" in
  multiaddr_*)
    MA_SRC="$(find "$HOME/.cargo/registry/src" -type d -path '*/multiaddr-0.19.*/src' 2>/dev/null | head -1 || true)"
    if [[ -n "$MA_SRC" ]]; then
      FOCUS_FILES=("$MA_SRC"/protocol.rs "$MA_SRC"/errors.rs "$MA_SRC"/lib.rs "$MA_SRC"/onion_addr.rs)
    fi
    REPORT_RG='multiaddr-0\.|fuzz_targets'
    ERR_SCAN_FILE="protocol.rs"
    ;;
  peer_id_from_bytes)
    ID_SRC="$(cd "$ROOT/../../identity/src" && pwd)"
    FOCUS_FILES=(
      "$ID_SRC"/keypair.rs "$ID_SRC"/peer_id.rs "$ID_SRC"/rsa.rs
      "$ID_SRC"/ed25519.rs "$ID_SRC"/secp256k1.rs "$ID_SRC"/ecdsa.rs "$ID_SRC"/error.rs
    )
    REPORT_RG='identity/src/|asn1_der-|fuzz_targets'
    ERR_SCAN_FILE="keypair.rs"
    ;;
  gossipsub_behaviour|gossipsub_strict_signed)
    GS_SRC="$(cd "$ROOT/../../protocols/gossipsub/src" && pwd)"
    FOCUS_FILES=(
      "$GS_SRC"/behaviour.rs "$GS_SRC"/mcache.rs "$GS_SRC"/peer_score.rs
      "$GS_SRC"/protocol.rs "$GS_SRC"/types.rs "$GS_SRC"/handler.rs
      "$GS_SRC"/fuzz.rs "$GS_SRC"/fuzz_handler.rs
    )
    REPORT_RG='protocols/gossipsub/src/|fuzz_targets'
    ERR_SCAN_FILE="protocol.rs"
    ;;
  gossipsub_handler)
    GS_SRC="$(cd "$ROOT/../../protocols/gossipsub/src" && pwd)"
    FOCUS_FILES=(
      "$GS_SRC"/handler.rs "$GS_SRC"/protocol.rs "$GS_SRC"/fuzz_handler.rs
      "$GS_SRC"/queue.rs
    )
    REPORT_RG='protocols/gossipsub/src/(handler|protocol|fuzz_handler|queue)|fuzz_targets'
    ERR_SCAN_FILE="handler.rs"
    ;;
  kademlia_behaviour)
    KAD_SRC="$(cd "$ROOT/../../protocols/kad/src" && pwd)"
    FOCUS_FILES=(
      "$KAD_SRC"/behaviour.rs "$KAD_SRC"/kbucket.rs "$KAD_SRC"/query.rs
      "$KAD_SRC"/query/peers/closest.rs
      "$KAD_SRC"/query/peers/closest/disjoint.rs
      "$KAD_SRC"/protocol.rs "$KAD_SRC"/record/store/memory.rs
      "$KAD_SRC"/handler.rs "$KAD_SRC"/fuzz.rs "$KAD_SRC"/fuzz_handler.rs
    )
    REPORT_RG='protocols/kad/src/|fuzz_targets'
    ERR_SCAN_FILE="behaviour.rs"
    ;;
  kademlia_handler)
    KAD_SRC="$(cd "$ROOT/../../protocols/kad/src" && pwd)"
    FOCUS_FILES=(
      "$KAD_SRC"/handler.rs "$KAD_SRC"/protocol.rs "$KAD_SRC"/fuzz_handler.rs
    )
    REPORT_RG='protocols/kad/src/(handler|protocol|fuzz_handler)|fuzz_targets'
    ERR_SCAN_FILE="handler.rs"
    ;;
  identify_behaviour)
    ID_SRC="$(cd "$ROOT/../../protocols/identify/src" && pwd)"
    FOCUS_FILES=(
      "$ID_SRC"/behaviour.rs "$ID_SRC"/handler.rs "$ID_SRC"/protocol.rs
      "$ID_SRC"/fuzz.rs "$ID_SRC"/fuzz_handler.rs
    )
    REPORT_RG='protocols/identify/src/|fuzz_targets'
    ERR_SCAN_FILE="behaviour.rs"
    ;;
  identify_handler)
    ID_SRC="$(cd "$ROOT/../../protocols/identify/src" && pwd)"
    FOCUS_FILES=(
      "$ID_SRC"/handler.rs "$ID_SRC"/protocol.rs "$ID_SRC"/fuzz_handler.rs
    )
    REPORT_RG='protocols/identify/src/(handler|protocol|fuzz_handler)|fuzz_targets'
    ERR_SCAN_FILE="handler.rs"
    ;;
  mplex_frame_codec|mplex_multiplexed_io)
    MPLEX_SRC="$(cd "$ROOT/../../muxers/mplex/src" && pwd)"
    FOCUS_FILES=(
      "$MPLEX_SRC"/codec.rs "$MPLEX_SRC"/io.rs "$MPLEX_SRC"/lib.rs
    )
    REPORT_RG='muxers/mplex/src/|fuzz_targets'
    ERR_SCAN_FILE="io.rs"
    ;;
  yamux_frame_header)
    YAMUX_SRC="$(cd "$ROOT/../../../yamux/yamux/src" && pwd)"
    FOCUS_FILES=(
      "$YAMUX_SRC"/lib.rs "$YAMUX_SRC"/frame/header.rs
      "$YAMUX_SRC"/connection.rs
    )
    # connection/ may be a dir — include if present
    if [[ -d "$YAMUX_SRC/connection" ]]; then
      FOCUS_FILES+=("$YAMUX_SRC"/connection/*.rs)
    fi
    REPORT_RG='yamux/|/fuzz_targets'
    ERR_SCAN_FILE="header.rs"
    ;;
  swarm_orchestrator)
    SWARM_SRC="$(cd "$ROOT/../../swarm/src" && pwd)"
    LIMITS_SRC="$(cd "$ROOT/../../misc/connection-limits/src" && pwd)"
    GOSSIP_SRC="$(cd "$ROOT/../../protocols/gossipsub/src" && pwd)"
    KAD_SRC="$(cd "$ROOT/../../protocols/kad/src" && pwd)"
    ID_SRC="$(cd "$ROOT/../../protocols/identify/src" && pwd)"
    FOCUS_FILES=(
      "$SWARM_SRC"/lib.rs "$SWARM_SRC"/connection.rs
      "$LIMITS_SRC"/lib.rs
      "$GOSSIP_SRC"/behaviour.rs "$GOSSIP_SRC"/handler.rs
      "$KAD_SRC"/behaviour.rs "$KAD_SRC"/handler.rs
      "$ID_SRC"/behaviour.rs "$ID_SRC"/handler.rs
      "$ROOT"/fuzz_targets/swarm_orchestrator.rs
    )
    REPORT_RG='swarm/src/|connection-limits/|gossipsub/src/(behaviour|handler)|kad/src/(behaviour|handler)|identify/src/(behaviour|handler)|fuzz_targets/swarm'
    ERR_SCAN_FILE="lib.rs"
    ;;
  swarm_circuit)
    RELAY_SRC="$(cd "$ROOT/../../protocols/relay/src" && pwd)"
    DCUTR_SRC="$(cd "$ROOT/../../protocols/dcutr/src" && pwd)"
    ID_SRC="$(cd "$ROOT/../../protocols/identify/src" && pwd)"
    SWARM_SRC="$(cd "$ROOT/../../swarm/src" && pwd)"
    FOCUS_FILES=(
      "$RELAY_SRC"/behaviour.rs "$RELAY_SRC"/priv_client.rs
      "$RELAY_SRC"/protocol/inbound_hop.rs "$RELAY_SRC"/protocol/outbound_hop.rs
      "$DCUTR_SRC"/behaviour.rs "$DCUTR_SRC"/handler/relayed.rs
      "$ID_SRC"/behaviour.rs
      "$SWARM_SRC"/lib.rs
      "$ROOT"/fuzz_targets/swarm_circuit.rs
    )
    REPORT_RG='relay/src/(behaviour|priv_client|protocol)|dcutr/src/(behaviour|handler)|identify/src/behaviour|swarm/src/lib|fuzz_targets/swarm_circuit'
    ERR_SCAN_FILE="behaviour.rs"
    ;;
  relay_behaviour)
    RELAY_SRC="$(cd "$ROOT/../../protocols/relay/src" && pwd)"
    FOCUS_FILES=(
      "$RELAY_SRC"/behaviour.rs "$RELAY_SRC"/behaviour/handler.rs
      "$RELAY_SRC"/protocol/inbound_hop.rs "$RELAY_SRC"/protocol/outbound_hop.rs
      "$RELAY_SRC"/protocol/inbound_stop.rs "$RELAY_SRC"/protocol/outbound_stop.rs
      "$RELAY_SRC"/fuzz.rs "$RELAY_SRC"/fuzz_handler.rs
      "$ROOT"/fuzz_targets/relay_behaviour.rs
    )
    REPORT_RG='relay/src/(behaviour|protocol|fuzz)|fuzz_targets/relay'
    ERR_SCAN_FILE="behaviour.rs"
    ;;
  dcutr_behaviour)
    DCUTR_SRC="$(cd "$ROOT/../../protocols/dcutr/src" && pwd)"
    FOCUS_FILES=(
      "$DCUTR_SRC"/behaviour.rs "$DCUTR_SRC"/handler/relayed.rs
      "$DCUTR_SRC"/protocol/inbound.rs "$DCUTR_SRC"/protocol/outbound.rs
      "$DCUTR_SRC"/fuzz.rs
      "$ROOT"/fuzz_targets/dcutr_behaviour.rs
    )
    REPORT_RG='dcutr/src/(behaviour|handler|protocol|fuzz)|fuzz_targets/dcutr'
    ERR_SCAN_FILE="behaviour.rs"
    ;;
  noise_handshake)
    NOISE_SRC="$(cd "$ROOT/../../transports/noise/src" && pwd)"
    FOCUS_FILES=(
      "$NOISE_SRC"/lib.rs "$NOISE_SRC"/fuzz.rs
      "$NOISE_SRC"/io.rs "$NOISE_SRC"/io/framed.rs "$NOISE_SRC"/io/handshake.rs
      "$NOISE_SRC"/protocol.rs
      "$ROOT"/fuzz_targets/noise_handshake.rs
    )
    REPORT_RG='transports/noise/src/|fuzz_targets/noise'
    ERR_SCAN_FILE="handshake.rs"
    ;;
esac

if ((${#FOCUS_FILES[@]})); then
  echo "==> llvm-cov HTML (focused) → $HTML_FOCUS"
  "$LLVM_COV" show "$BIN" \
    -instr-profile="$PROF" \
    -format=html \
    -output-dir="$HTML_FOCUS" \
    "${FOCUS_FILES[@]}" \
    2>/dev/null || true
fi

echo "==> llvm-cov report (focused rows)"
"$LLVM_COV" report "$BIN" -instr-profile="$PROF" 2>/dev/null | rg "$REPORT_RG" || true

echo "==> text dump + zero-hit Err scan → $TEXT"
"$LLVM_COV" show "$BIN" -instr-profile="$PROF" -format=text \
  -show-line-counts-or-regions \
  2>/dev/null > "$TEXT/all.txt" || true

if ((${#FOCUS_FILES[@]})); then
  for src in "${FOCUS_FILES[@]}"; do
    base="$(basename "$src")"
    awk -v want="$base" '
      index($0, want) { p=1; print; next }
      /^\// || /^home\// { if (index($0, want) == 0) p=0 }
      p { print }
    ' "$TEXT/all.txt" > "$TEXT/$base.cov.txt" || true
  done
fi

if [[ -n "$ERR_SCAN_FILE" && -f "$TEXT/$ERR_SCAN_FILE.cov.txt" ]]; then
  echo "==> zero-hit lines mentioning Err ($ERR_SCAN_FILE):"
  rg '^\s+[0-9]+\|\s+0\|.*Err' "$TEXT/$ERR_SCAN_FILE.cov.txt" | head -40 \
    || echo "(none)"
fi

echo
echo "Open: $HTML/index.html"
[[ -d "$HTML_FOCUS" ]] && echo "Focus: $HTML_FOCUS/index.html"
echo "Tips: ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run $TARGET -- -print_coverage=1 -print_funcs=0"
echo "      ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz cmin $TARGET"
